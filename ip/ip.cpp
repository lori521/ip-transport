#include "ip.hpp"
#include "utils/utils.h"
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
}

ipv4_packet_t::ipv4_packet_t(std::vector<uint8_t> raw) {
  this->header = ipv4_packet_header(raw);
  this->data =
      std::vector<uint8_t>(raw.begin() + header.header_length, raw.end());
}

ipv4_packet_t::ipv4_packet_t(std::vector<uint8_t> payload,
                             ipv4_fragment_info_t fragment_info,
                             uint32_t destination, ipv4_settings_t &settings) {
  this->header =
      ipv4_packet_header(payload.size(), fragment_info, destination, settings);
  this->data = payload;

  // Calculate checksum
  std::vector<uint8_t> bytes = this->dump_network_packet();
  if (bytes.size() & 1 == 0) {
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
ipv4_packet_batch_t IPv4::GeneratePackets(std::vector<uint8_t> &payload,
                                          char destination[15]) {
  // Parse char* to uin32_t
  uint32_t destination_addr;

  ipv4_packet_batch_t packets;
  packets.packet_id = random();

  if (!this->settings.allow_fragmentation) {
    if (payload.size() + settings.options.size() +
            ipv4_packet_header::FIXED_PART_HEADER_SIZE >
        settings.max_fragment_len) {
      throw std::runtime_error(
          "Throwing packet, does not respect fragmentation constraints");
    }
  } else if (payload.size() + settings.options.size() +
                 ipv4_packet_header::FIXED_PART_HEADER_SIZE >
             settings.max_fragment_len) {
    // Send multiple packets with size aligned to 8 bytes
    size_t packet_payload_size = (settings.max_fragment_len -
                                  ipv4_packet_header::FIXED_PART_HEADER_SIZE -
                                  settings.options.size()) >>
                                 8 << 8;
    if (packet_payload_size == 0) {
      throw std::runtime_error(
          "Cannot fragment this package max_fragment_len is too small\n");
    }

    size_t number_packets = ((payload.size() - 1) / packet_payload_size + 1);
    for (int i = 0; i < number_packets; i++) {
      ipv4_fragment_info_t fragment_info = ipv4_fragment_info_t{
          .is_fragmented = true,
          .fragment_id = packets.packet_id,
          .fragment_offset = (uint16_t)((i * packet_payload_size) >> 8),
          .is_last = (i + 1 == number_packets)};

      ipv4_packet_t packet =
          ipv4_packet_t(payload, fragment_info, destination_addr, settings);
      packets.add_packet(packet);
    }

    return packets;
  }

  // Send one packet
  ipv4_fragment_info_t fragment_info =
      ipv4_fragment_info_t{.is_fragmented = false,
                           .fragment_id = packets.packet_id,
                           .fragment_offset = 0,
                           .is_last = true};

  ipv4_packet_t packet =
      ipv4_packet_t(payload, fragment_info, destination_addr, settings);
  packets.add_packet(packet);

  return packets;
}

void IPv4::ReadPackets(std::vector<uint8_t> &data, ipv4_packet_batch_t &batch) {
  ipv4_packet_t packet = ipv4_packet_t(data);
  if (packet.header.flags & MORE_FRAGMENTS == 0) {
    batch.done = true;
  }

  batch.add_packet(packet);
}
void ipv4_packet_batch_t::add_packet(ipv4_packet_t packet) {
  if (ipv4_packets.size() == 0) {
    // No checks just add
    ipv4_packets.push_back(packet);
  } else {
    // Make some sanity checks, trust first packet
    if (ipv4_packets[0].header.packet_id != packet.header.packet_id) {
      throw std::invalid_argument(
          "Cannot add to batch packet with different id");
    }
    ipv4_packets.push_back(packet);
  }
}

bool compare_by_fragment_offset(const ipv4_packet_t &A,
                                const ipv4_packet_t &B) {
  return A.header.fragment_offset < B.header.fragment_offset;
}

std::vector<uint8_t> ipv4_packet_batch_t::get_payload() {
  // sort by fragment offset to make sure I have the entire payload
  std::sort(this->ipv4_packets.begin(), this->ipv4_packets.end(),
            compare_by_fragment_offset);

  std::vector<uint8_t> merged_payload;
  size_t expected_packet_offset = 0;
  for (int i = 0; i < ipv4_packets.size(); i++) {
    ipv4_packet_t pkt = ipv4_packets[i];
    if (expected_packet_offset != pkt.header.fragment_offset) {
      throw std::runtime_error(
          "Payload was not received entirely in fragmentation");
    }

    merged_payload.insert(merged_payload.end(), pkt.data.begin(),
                          pkt.data.end());

    expected_packet_offset = expected_packet_offset + (pkt.data.size() >> 8);
  }
  return merged_payload;
}