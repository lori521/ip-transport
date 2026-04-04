#pragma once
#include "header/header.hpp"
#include "utils/utils.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "header/header.hpp"

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

struct ipv4_settings_t {
  uint32_t device_ip_address;
  ipv4_header_protocol_t protocol;
  uint8_t ttl = 64;
  service_type_t service_type =
      (service_type_t)(LOW_DELAY | HIGH_THROUGHPUT | HIGH_RELIABILITY);
  bool forward_traffic = false;

  bool allow_fragmentation = false;
  size_t max_fragment_len = MAX_IP_PACKET_SIZE;

  ipv4_settings_t(char ip_address[15], ipv4_header_protocol_t protocol)
      : protocol(protocol) {

    if (decode_ip_address(ip_address, this->device_ip_address) == false) {
      std::printf("IP Address wrongly formatted\n");
      std::exit(1);
    }
  }
};
