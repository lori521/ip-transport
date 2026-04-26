#include "routing.hpp"
#include "utils/utils.hpp"
bool ip_router_mask_t::matches(uint32_t ip) {
  uint32_t bit_mask = -1;
  bit_mask <<= (32 - this->mask);

  return (ip & bit_mask) == this->ip_prefix;
}

IPv4Router::IPv4Router(uint32_t ip, Ethernet *eth_default_gateway) {
  this->ip_table.insert(ip_router_mask_t{
      .ip_prefix = 0, .mask = 0, .eth = eth_default_gateway, .host_ip = ip});
}
IPv4Router::IPv4Router(char *ip, Ethernet *eth_default_gateway) {
  uint32_t ip_addr;
  if (!decode_ip_address(ip, ip_addr)) {
    printf("Could not decode ip addr\n");
    return;
  }
  this->ip_table.insert(ip_router_mask_t{.ip_prefix = 0,
                                         .mask = 0,
                                         .eth = eth_default_gateway,
                                         .host_ip = ip_addr});
}
IPv4Resolve IPv4Router::where(uint32_t ip) {
  for (ip_router_mask_t mask : this->ip_table) {
    if (mask.matches(ip)) {
      char ip_send[20], ip_matched[20];
      encode_ip_address(ip, ip_send);
      encode_ip_address(mask.host_ip, ip_matched);
      printf("Matched ip %s with mask: %d on host: %s\n", ip_send, mask.mask,
             ip_matched);
      return IPv4Resolve{
          .found = true, .eth = mask.eth, .host_ip = mask.host_ip};
    }
  }
  return IPv4Resolve{.found = false};
}

vector<Ethernet *> IPv4Router::fetchAll() {
  vector<Ethernet *> eths;
  for (auto &entry : this->ip_table) {
    eths.push_back(entry.eth);
  }

  return eths;
}

void IPv4Router::AddEntry(uint32_t ip, uint32_t ip_prefix, uint mask,
                          Ethernet *eth) {
  this->ip_table.insert(ip_router_mask_t{
      .ip_prefix = ip_prefix, .mask = mask, .eth = eth, .host_ip = ip});
}

void IPv4Router::AddEntry(char *ip, char *ip_prefix, uint mask, Ethernet *eth) {
  uint32_t decoded_ip;
  if (!decode_ip_address(ip, decoded_ip)) {
    printf("Could not decode ip adddress\n");
    return;
  }
  uint32_t decoded_ip_prefix;
  if (!decode_ip_address(ip_prefix, decoded_ip_prefix)) {
    printf("Could not decode ip prefix\n");
    return;
  }
  AddEntry(decoded_ip, decoded_ip_prefix, mask, eth);
}

void IPv4Router::AddFullEntry(uint32_t ip, Ethernet *eth) {
  AddEntry(ip, ip, 32, eth);
}
void IPv4Router::AddFullEntry(char *ip, Ethernet *eth) {
  AddEntry(ip, ip, 32, eth);
}