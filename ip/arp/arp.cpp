#include "arp.hpp"
#include "pico/time.h"
#include "utils/utils.hpp"
#include <iostream>
uint32_t arp_packet_t::size() {
  return this->hwd.hardware_len * 2 + this->prot.protocol_len * 2 + 2 * 2 + 2 +
         2; // 2 * mac + 2* ip + hwd_type + prot_type + hwd_len + prot_len +
            // op_type
}
std::vector<uint8_t> arp_packet_t::dump_arp_packet() {
  std::vector<uint8_t> payload;

  uint16_t hwd_type;
  memcpy(&hwd_type, &this->hwd.hardware_type, sizeof(hwd_type));
  push_uint16_n(payload, hwd_type);

  uint16_t prot_type;
  memcpy(&prot_type, &this->prot.protocol_type, sizeof(prot_type));
  push_uint16_n(payload, prot_type);

  payload.push_back(this->hwd.hardware_len);
  payload.push_back(this->prot.protocol_len);

  uint16_t op_type;
  memcpy(&op_type, &this->p_type, sizeof(op_type));
  push_uint16_n(payload, op_type);

  for (int i = 0; i < this->hwd.hardware_len; i++) {
    payload.push_back(this->src_mac[i]);
  }

  push_uint32_n(payload, this->src_ip_addr);

  for (int i = 0; i < this->hwd.hardware_len; i++) {
    payload.push_back(this->dest_mac[i]);
  }

  push_uint32_n(payload, this->dest_ip_addr);

  return payload;
}

bool arp_packet_t::read_raw(std::vector<uint8_t> &payload) {
  size_t idx = 0;

  uint16_t hwd_type = read_uint16_n(payload, idx);
  memcpy(&this->hwd.hardware_type, &hwd_type, sizeof(hwd_type));
  idx += 2;

  uint16_t prot_type = read_uint16_n(payload, idx);
  memcpy(&this->prot.protocol_type, &prot_type, sizeof(prot_type));
  idx += 2;

  this->hwd.hardware_len = payload[idx++];
  this->prot.protocol_len = payload[idx++];

  uint16_t op_type = read_uint16_n(payload, idx);
  memcpy(&this->p_type, &op_type, sizeof(op_type));
  idx += 2;

  for (int i = 0; i < this->hwd.hardware_len; i++) {
    this->src_mac[i] = payload[idx++];
  }

  this->src_ip_addr = read_uint32_n(payload, idx);
  idx += 4;

  for (int i = 0; i < this->hwd.hardware_len; i++) {
    this->dest_mac[i] = payload[idx++];
  }

  this->dest_ip_addr = read_uint32_n(payload, idx);
  idx += 4;

  return true;
}
// Returns true if it is a valid request
bool ARP::ProcessRequest(std::vector<uint8_t> &arp_payload, uint8_t mac[6],
                         uint32_t &ip) {
  arp_packet_t pkt;
  if (!pkt.read_raw(arp_payload)) {
    return false;
  }

  memcpy(mac, pkt.src_mac, pkt.hwd.hardware_len);
  ip = pkt.src_ip_addr;

  if (pkt.p_type == ARPPacketType::RESPONSE) {
    return false;
  }
  if (pkt.dest_ip_addr != this->device_ip) {
    return false;
  }

  return true;
}

bool ARP::UpdateEntry(std::vector<uint8_t> &arp_payload) {
  arp_packet_t pkt;
  if (!pkt.read_raw(arp_payload)) {
    return false;
  }
  if (pkt.dest_ip_addr != this->device_ip) {
    printf("ARP Packet not mean for me\n");
    return false;
  }
  arp_entry_t entry;
  entry.timestamp_expiry = to_us_since_boot(get_absolute_time()) +
                           this->time_mac_expiration_s * 1000000;
  memcpy(entry.mac, pkt.src_mac, pkt.hwd.hardware_len);

  this->arp_table[pkt.src_ip_addr] = entry;

  printf("Updated entry in ARP table\n");
  return true;
}
std::vector<uint8_t> ARP::CraftResponse(std::vector<uint8_t> &arp_payload) {
  arp_packet_t pkt;
  if (!pkt.read_raw(arp_payload)) {
    return {};
  }
  arp_packet_t response(ARPPacketType::RESPONSE, this->device_mac, pkt.src_mac,
                        this->device_ip, pkt.src_ip_addr);
  return response.dump_arp_packet();
}
bool ARP::GetMac(uint32_t ip_addr, uint8_t mac[6]) {
  if (this->arp_table.find(ip_addr) == this->arp_table.end()) {
    printf("Could not find ARP entry\n");
    return false;
  }

  arp_entry_t entry = this->arp_table[ip_addr];
  if (to_us_since_boot(get_absolute_time()) > entry.timestamp_expiry) {
    printf("ARP entry expired");
    this->arp_table.erase(ip_addr);
    return false;
  }

  memcpy(mac, entry.mac, sizeof(entry.mac));

  char ip[20];
  encode_ip_address(ip_addr, ip);
  printf("Matched %s on %hhx %hhx %hhx %hhx %hhx %hhx\n", ip, mac[0], mac[1],
         mac[2], mac[3], mac[4], mac[5]);
  return true;
}

std::vector<uint8_t> ARP::GenerateRequestPacket(uint32_t ip_addr) {
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  arp_packet_t pkt(ARPPacketType::REQUEST, this->device_mac, broadcast,
                   this->device_ip, ip_addr);
  return pkt.dump_arp_packet();
}

void ARP::QueuePacket(uint32_t ip_addr, std::vector<uint8_t> payload) {
  this->queued[ip_addr].push_back(payload);
}

std::vector<std::vector<uint8_t>> ARP::DequeueAllPacketsOnIP(uint32_t ip_addr) {
  auto packets = this->queued[ip_addr];
  this->queued[ip_addr].clear();
  return packets;
}
