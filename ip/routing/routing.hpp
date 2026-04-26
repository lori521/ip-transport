#pragma once

#include "ethernet.hpp"
#include <set>

struct ip_router_mask_t {
  uint32_t ip_prefix;
  uint mask;
  Ethernet *eth;
  uint32_t host_ip;

  bool matches(uint32_t ip);
};
struct IPv4Resolve {
  bool found;
  Ethernet *eth;
  uint32_t host_ip;
};

struct IPv4RouterMaskComparator {
  bool operator()(const ip_router_mask_t &A, const ip_router_mask_t &B) const {
    if (A.mask != B.mask)
      return A.mask > B.mask;
    return A.ip_prefix < B.ip_prefix;
  }
};
class IPv4Router {
  std::set<ip_router_mask_t, IPv4RouterMaskComparator> ip_table;

public:
  IPv4Router() {}
  IPv4Router(uint32_t default_gateway_ip, Ethernet *eth_default_gateway);
  IPv4Router(char *default_gateway_ip, Ethernet *eth_default_gateway);

  void AddEntry(uint32_t ip, uint32_t ip_prefix, uint mask, Ethernet *eth);
  void AddFullEntry(uint32_t ip, Ethernet *eth);
  void AddEntry(char *ip, char *ip_prefix, uint mask, Ethernet *eth);
  void AddFullEntry(char *ip, Ethernet *eth);

  IPv4Resolve where(uint32_t ip);
  vector<Ethernet *> fetchAll();
};