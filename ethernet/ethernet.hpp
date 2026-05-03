#ifndef ETHERNET_HPP
#define ETHERNET_HPP

#include "../manchester_nonblock/manchester.hpp"
#include "pico/stdlib.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

using namespace std;

#define MAC_ADDRESS_LEN 6
#define MAC_HEADER_LEN (2 * MAC_ADDRESS_LEN + 2) // 6 + 6 + 2
#define FCS_LEN 4

enum class EthernetType : uint16_t {
  IPv4 = 0x0008,
  ARP = 0x0608,
};
class Ethernet {
private:
  Manchester &m;
  uint8_t source_mac[MAC_ADDRESS_LEN];
  uint32_t fcs;

  uint32_t calculate_fcs(const uint8_t *data, size_t length);

  vector<uint8_t> eth_encap(const uint8_t *payload, uint32_t payload_len,
                            EthernetType eth_type,
                            uint8_t destination_mac[MAC_ADDRESS_LEN]);
  vector<uint8_t> eth_decap(uint8_t *frame, uint32_t frame_data_length,
                            EthernetType *eth_type,
                            uint8_t destination_mac[MAC_ADDRESS_LEN]);

public:
  Ethernet(Manchester &m, const uint8_t *source_mac_address);
  bool Read(std::vector<uint8_t> &payload,
            uint8_t destination_mac[MAC_ADDRESS_LEN], EthernetType *eth_type);
  bool Peek(std::vector<uint8_t> &payload,
            uint8_t destination_mac[MAC_ADDRESS_LEN], EthernetType *eth_type);
  bool Send(std::vector<uint8_t> payload,
            uint8_t destination_mac[MAC_ADDRESS_LEN],
            EthernetType eth_type = EthernetType::IPv4);
};

#endif // ETHERNET_HPP