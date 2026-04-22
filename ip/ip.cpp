#include "ip.hpp"
#include "utils/utils.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <random>
#include <stdexcept>
#include <utility>

// IPv4 Packet
std::vector<uint8_t> ipv4_packet_t::dump_network_packet() {
  std::vector<uint8_t> network_payload;

  // Copy header
  std::vector<uint8_t> header_payload = this->header.dump_network_header();
  network_payload.insert(network_payload.end(), header_payload.begin(),
                         header_payload.end());

  // Copy data
  network_payload.insert(network_payload.end(), this->data.begin(),
                         this->data.end());
  return network_payload;
}

bool ipv4_packet_t::read_raw(std::vector<uint8_t> raw) {
  if (this->header.read_raw(raw) == false) {
    printf("Could not read header from raw data\n");
    return false;
  }

  this->data = std::vector<uint8_t>(raw.begin() + (header.header_length << 2),
                                    raw.end());
  return true;
}

ipv4_packet_t::ipv4_packet_t(std::vector<uint8_t> payload,
                             ipv4_fragment_info_t fragment_info,
                             uint32_t destination, ipv4_settings_t &settings,
                             const ipv4_options_t &ip_options) {
  this->header = ipv4_packet_header(payload.size(), fragment_info, destination,
                                    settings, ip_options);
  this->data = payload;
}

// This throws error if:
// - allow_fragmentation is set to false, and network requires fragmentation
// - allow_fragmentation is true, but network max_len is smaller than a minimum
// size
bool IPv4::GeneratePackets(std::vector<uint8_t> &payload,
                           uint32_t destination_addr,
                           ipv4_packet_batch_t &batch,
                           const ipv4_options_t &ip_options) {
  batch.packet_id = random();

  if (!this->settings.allow_fragmentation) {
    if (payload.size() + ip_options.size() +
            ipv4_packet_header::FIXED_PART_HEADER_SIZE >
        settings.max_fragment_len) {
      std::printf(
          "Throwing packet, does not respect fragmentation constraints\n");
      return false;
    }
  } else if (payload.size() + ip_options.size() +
                 ipv4_packet_header::FIXED_PART_HEADER_SIZE >
             settings.max_fragment_len) {

    // Send multiple packets with size aligned to 8 bytes
    size_t packet_payload_size =
        (((settings.max_fragment_len -
           ipv4_packet_header::FIXED_PART_HEADER_SIZE - ip_options.size()) >>
          3)
         << 3);
    if (packet_payload_size == 0) {
      std::printf(
          "Cannot fragment this package max_fragment_len is too small\n");
      return false;
    }

    size_t number_packets =
        ((payload.size() + (packet_payload_size - 1)) / packet_payload_size);
    for (int i = 0; i < number_packets; i++) {
      ipv4_fragment_info_t fragment_info = ipv4_fragment_info_t{
          .is_fragmented = true,
          .fragment_id = batch.packet_id,
          .fragment_offset = (uint16_t)((i * packet_payload_size) >> 3),
          .is_last = (i + 1 == number_packets)};

      std::vector<uint8_t> fragment_payload(
          payload.begin() + (i * packet_payload_size),
          payload.begin() +
              min(((i + 1) * packet_payload_size), payload.size()));

      ipv4_packet_t packet =
          ipv4_packet_t(fragment_payload, fragment_info, destination_addr,
                        settings, ip_options);
      batch.add_packet(packet);
    }

    return true;
  }

  // Send one packet
  ipv4_fragment_info_t fragment_info =
      ipv4_fragment_info_t{.is_fragmented = false,
                           .fragment_id = batch.packet_id,
                           .fragment_offset = 0,
                           .is_last = true};

  ipv4_packet_t packet = ipv4_packet_t(payload, fragment_info, destination_addr,
                                       settings, ip_options);
  batch.add_packet(packet);

  return true;
}
bool IPv4::GeneratePackets(std::vector<uint8_t> &payload, uint32_t destination,
                           ipv4_packet_batch_t &batch) {
  return this->GeneratePackets(payload, destination, batch, ipv4_options_t());
}

bool ipv4_packet_batch_t::add_packet(ipv4_packet_t packet) {
  if (ipv4_packets.size() == 0) {
    // No checks just add
    this->packet_id = packet.header.packet_id;
    ipv4_packets.insert(packet);

    // Check if it's a lonely packet
    if ((packet.header.flags & MORE_FRAGMENTS) == 0 &&
        packet.header.fragment_offset == 0) {
      this->done = true;
    }

  } else {
    // Make some sanity checks
    if (this->packet_id != packet.header.packet_id) {
      std::printf("Cannot add to batch packet with different id");
      return false;
    }
    ipv4_packets.insert(packet);

    this->done = true;
    size_t expected_packet_offset = 0;
    for (auto pkt : ipv4_packets) {
      if (expected_packet_offset != pkt.header.fragment_offset) {
        this->done = false;
        break;
      }

      expected_packet_offset = expected_packet_offset + (pkt.data.size() >> 3);
    }

    // Make final check that last packet has MF = 0
    if ((ipv4_packets.rbegin()->header.flags & MORE_FRAGMENTS) != 0) {
      this->done = false;
    }
  }
  return true;
}

bool ipv4_packet_batch_t::get_payload(std::vector<uint8_t> &merged_payload) {
  size_t expected_packet_offset = 0;
  for (auto pkt : ipv4_packets) {
    if (expected_packet_offset != pkt.header.fragment_offset) {
      std::printf("Payload was not received entirely in fragmentation");
      return false;
    }

    merged_payload.insert(merged_payload.end(), pkt.data.begin(),
                          pkt.data.end());

    expected_packet_offset = expected_packet_offset + (pkt.data.size() >> 3);
  }
  return true;
}

bool IPv4::ReadPackets(ipv4_packet_t packet) {

  if (this->packets.find(packet.header.packet_id) == this->packets.end()) {
    // Add new batch
    ipv4_packet_batch_t new_batch;
    if (!new_batch.add_packet(packet)) {
      printf("Could not add packet to batch\n");
      return false;
    }
    this->packets[packet.header.packet_id] = new_batch;
  } else {
    if (!this->packets[packet.header.packet_id].add_packet(packet)) {
      printf("Could not add packet to batch\n");
      return false;
    }
  }
  return true;
}

bool IPv4::PopFinishedBatch(ipv4_packet_batch_t &finished) {
  for (const auto &entries : this->packets) {
    if (entries.second.done == true) {
      finished = entries.second;
      this->packets.erase(finished.packet_id);
      return true;
    }
  }
  return false;
}

bool IPv4::SendIPPacket(vector<uint8_t> &payload, char *destination,
                        uint8_t *destination_mac) {
  uint32_t destination_addr;
  if (decode_ip_address(destination, destination_addr) == false) {
    printf("Could not parse destination addr\n");
    return false;
  }

  return SendIPPacket(payload, destination_addr, destination_mac);
}
bool IPv4::SendIPPacket(vector<uint8_t> &payload, uint32_t destination_addr,
                        uint8_t *destination_mac) {
  Ethernet *eth = router.where(destination_addr);
  if (eth == NULL) {
    printf("Throwed packet. It doesn't match any entry in router\n");
    return false;
  }

  ipv4_packet_batch_t batch;
  if (this->GeneratePackets(payload, destination_addr, batch) == false) {
    printf("Could not generate IP packets\n");
    return false;
  }

  for (ipv4_packet_t pkt : batch.ipv4_packets) {
    vector<uint8_t> ip_payload = pkt.dump_network_packet();

    if (!eth->Send(ip_payload, destination_mac)) {
      return false;
    }
  }
  return true;
}
bool IPv4::RedirectIPPacket(ipv4_packet_t packet) {
  if (packet.header.ttl == 0) {
    printf("TTL is 0\n");
    return false;
  }

  packet.header.redirect();
  Ethernet *eth = router.where(packet.header.destination_ip_address);
  if (eth == NULL) {
    printf("Throwed packet. It doesn't match any entry in router\n");
    return false;
  }

  vector<uint8_t> ip_payload = packet.dump_network_packet();
  uint8_t broadcast_mac[MAC_ADDRESS_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  if (!eth->Send(ip_payload, broadcast_mac)) {
    return false;
  }

  return true;
}

// Reads first whole IP packet
bool IPv4::ReadIPPacket(vector<uint8_t> &payload, ipv4_packet_header &header) {
  vector<uint8_t> eth_payload;

  vector<Ethernet *> eths = this->router.fetchAll();
  for (Ethernet *eth : eths) {
    if (eth->Read(eth_payload, NULL, NULL)) {
      ipv4_packet_t packet;
      packet.read_raw(eth_payload);
      if (packet.header.destination_ip_address !=
          this->settings.device_ip_address) {
        if (this->RedirectIPPacket(packet) == false) {
          printf("Could not redirect ip packet\n");
          continue;
        }
      } else {
        if (this->ReadPackets(packet) == false) {
          printf("Could not read ip packet\n");
          continue;
        }
      }
    }
  }

  ipv4_packet_batch_t batch;
  if (!this->PopFinishedBatch(batch)) {
    return false;
  }

  // printf("Have packet\n");
  payload.clear();
  batch.get_payload(payload);
  header = batch.ipv4_packets.begin()->header;

  if (header.ttl == 0) {
    return false;
  }

  // TODO Optional: cleanup map from ip batches that where never completed

  return true;
}

bool IPv4::ReadIPPacket(vector<uint8_t> &payload, char *source) {
  ipv4_packet_header header;
  if (!this->ReadIPPacket(payload, header)) {
    return false;
  }

  if (source != NULL) {
    encode_ip_address(header.source_ip_address, source);
  }

  return true;
}

uint32_t IPv4::GetSourceAddress() { return this->settings.device_ip_address; }

void IPv4::GetSourceAddress(char *src_addr) {
  return encode_ip_address(GetSourceAddress(), src_addr);
}