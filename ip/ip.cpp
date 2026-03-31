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
                             uint32_t destination, ipv4_settings_t &settings) {
  this->header =
      ipv4_packet_header(payload.size(), fragment_info, destination, settings);
  this->data = payload;

  // Calculate checksum
  std::vector<uint8_t> bytes = this->dump_network_packet();
  if ((bytes.size() & 1) == 0) {
    bytes.push_back(0);
  }

  uint32_t sum = 0;
  for (int i = 0; i < bytes.size(); i += 2) {
    uint16_t word = read_uint16_n(bytes, i);
    sum += word;
    sum = (sum & 0b1111111111111111) + (sum >> 16);
  }

  this->header.header_check_sum = (~sum) & 0b1111111111111111;
}

// This throws error if:
// - allow_fragmentation is set to false, and network requires fragmentation
// - allow_fragmentation is true, but network max_len is smaller than a minimum
// size
bool IPv4Sender::GeneratePackets(std::vector<uint8_t> &payload,
                                 char *destination,
                                 ipv4_packet_batch_t &batch) {
  uint32_t destination_addr;
  if (decode_ip_address(destination, destination_addr) == false) {
    printf("Could not parse destination addr\n");
    return false;
  }

  batch.packet_id = random();

  if (!this->settings.allow_fragmentation) {
    if (payload.size() + settings.options.size() +
            ipv4_packet_header::FIXED_PART_HEADER_SIZE >
        settings.max_fragment_len) {
      std::printf(
          "Throwing packet, does not respect fragmentation constraints\n");
      return false;
    }
  } else if (payload.size() + settings.options.size() +
                 ipv4_packet_header::FIXED_PART_HEADER_SIZE >
             settings.max_fragment_len) {

    // Send multiple packets with size aligned to 8 bytes
    size_t packet_payload_size = (((settings.max_fragment_len -
                                    ipv4_packet_header::FIXED_PART_HEADER_SIZE -
                                    settings.options.size()) >>
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
          payload.begin() + ((i + 1) * packet_payload_size));

      ipv4_packet_t packet = ipv4_packet_t(fragment_payload, fragment_info,
                                           destination_addr, settings);
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

  ipv4_packet_t packet =
      ipv4_packet_t(payload, fragment_info, destination_addr, settings);
  batch.add_packet(packet);

  return true;
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

bool IPv4Receiver::ReadPackets(std::vector<uint8_t> &data) {
  ipv4_packet_t packet;

  if (!packet.read_raw(data)) {
    printf("Could not parse data in payload");
    return false;
  }

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

std::vector<ipv4_packet_batch_t> IPv4Receiver::PopFinishedBatch() {
  std::vector<ipv4_packet_batch_t> finished;
  for (const auto &entries : this->packets) {
    if (entries.second.done == true) {
      finished.push_back(entries.second);
    }
  }
  for (const auto &f : finished) {
    this->packets.erase(f.packet_id);
  }
  return finished;
}
