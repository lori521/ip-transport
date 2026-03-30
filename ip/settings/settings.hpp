#pragma once
#include "header/header.hpp"
#include <cstdint>

struct ipv4_settings_t {
  uint32_t device_ip_address;
  ipv4_header_protocol_t protocol;
  uint8_t ttl = 64;
  service_type_t service_type =
      (service_type_t)(LOW_DELAY | HIGH_THROUGHPUT | HIGH_RELIABILITY);
  bool forward_traffic = false;

  bool allow_fragmentation = false;
  size_t max_fragment_len = 0;

  ipv4_options_t options;

  ipv4_settings_t(uint32_t ip_address, ipv4_header_protocol_t protocol)
      : device_ip_address(ip_address), protocol(protocol) {}
};
