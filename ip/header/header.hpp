#pragma once

#include "settings/settings.hpp"
#include <cstdint>
#include <vector>

const size_t MAX_IP_PACKET_SIZE = ((1 << 16) - 1);
enum service_type_t {
  LOW_DELAY = 1 << 3,
  HIGH_THROUGHPUT = 1 << 4,
  HIGH_RELIABILITY = 1 << 5,
};

enum ipv4_header_protocol_t {
  ICMP = 1,
  TCP = 6,
  UDP = 17,
};

enum ipv4_fragment_options_t {
  DO_NOT_FRAGMENT = 1 << 1,
  MORE_FRAGMENTS = 1 << 2
};

// This is just a wrapper over vector, but I can add functionalities later to it
struct ipv4_options_t {
  std::vector<uint8_t> data;

  std::vector<uint8_t> dump_options();

  ipv4_options_t();
  ipv4_options_t(std::vector<uint8_t> raw_data);

  size_t size();
};

struct ipv4_fragment_info_t {
  bool is_fragmented;
  uint16_t fragment_id;
  uint16_t fragment_offset;
  bool is_last;
};

struct ipv4_packet_header {

  // These fields have fixed size
  uint8_t version = 4;   // default 4, occupies 4 bits
  uint8_t header_length; // calculated after, occupies 4 bits
  uint8_t service_type;
  uint16_t total_length; // header + data
  uint16_t packet_id;
  uint8_t flags;            // occupies 3 bits
  uint16_t fragment_offset; // occupies 13 bits
  uint8_t ttl;
  uint8_t protocol;
  uint16_t header_check_sum;
  uint32_t source_ip_address;
  uint32_t destination_ip_address;

  static constexpr size_t FIXED_PART_HEADER_SIZE = 20;

  ipv4_options_t options;

  std::vector<uint8_t> dump_network_header();

  ipv4_packet_header();
  ipv4_packet_header(std::vector<uint8_t> raw);
  ipv4_packet_header::ipv4_packet_header(uint16_t payload_size,
                                         ipv4_fragment_info_t fragment_info,
                                         uint32_t destination,
                                         ipv4_settings_t &settings);
};