#pragma once
#include "utils/utils.hpp"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <queue>
#include <unordered_map>
#include <vector>
enum class ARPHardwareType : uint16_t { ETHERNET = 1 };
struct ARPHardware {
  ARPHardwareType hardware_type;
  uint8_t hardware_len;

  ARPHardware() {}
  ARPHardware(ARPHardwareType hardware_type, uint8_t hardware_len)
      : hardware_type(hardware_type), hardware_len(hardware_len) {}
};

enum class ARPProtocolType : uint16_t { IPV4 = 0x0800 };
struct ARPProtocol {
  ARPProtocolType protocol_type;
  uint8_t protocol_len;

  ARPProtocol() {}
  ARPProtocol(ARPProtocolType protocol_type, uint8_t protocol_len)
      : protocol_type(protocol_type), protocol_len(protocol_len) {};
};

enum class ARPPacketType : uint16_t {
  REQUEST = 1,
  RESPONSE = 2,
};

// This is an implementation specific for IPv4 + Ethernet, the above types can
// be used for other protocols and hardware
struct arp_packet_t {
  ARPHardware hwd;
  ARPProtocol prot;
  ARPPacketType p_type;
  uint8_t src_mac[6];
  uint8_t dest_mac[6];
  uint32_t src_ip_addr;
  uint32_t dest_ip_addr;

  arp_packet_t() {}
  arp_packet_t(ARPPacketType packet_type, uint8_t src_mac[6],
               uint8_t dest_mac[6], uint32_t src_ip_addr, uint32_t dest_ip_addr)
      : hwd(ARPHardwareType::ETHERNET, 6), prot(ARPProtocolType::IPV4, 4),
        src_ip_addr(src_ip_addr), dest_ip_addr(dest_ip_addr),
        p_type(packet_type) {
    memcpy(this->src_mac, src_mac, this->hwd.hardware_len);
    memcpy(this->dest_mac, dest_mac, this->hwd.hardware_len);
  }
  std::vector<uint8_t> dump_arp_packet();
  bool read_raw(std::vector<uint8_t> &payload);
  uint32_t size();
};

struct arp_entry_t {
  uint8_t mac[6];
  uint64_t timestamp_expiry;
};
class ARP {
  uint8_t device_mac[6];
  uint32_t device_ip;
  uint64_t time_mac_expiration_s;
  std::unordered_map<uint32_t, arp_entry_t> arp_table;
  std::unordered_map<uint32_t, std::vector<std::vector<uint8_t>>> queued;

public:
  bool ProcessRequest(std::vector<uint8_t> &arp_payload, uint8_t mac[6],
                      uint32_t &ip);
  bool UpdateEntry(std::vector<uint8_t> &arp_payload);
  std::vector<uint8_t> CraftResponse(std::vector<uint8_t> &arp_payload);
  bool GetMac(uint32_t ip_addr, uint8_t mac[6]);
  std::vector<uint8_t> GenerateRequestPacket(uint32_t ip_addr);

  void QueuePacket(uint32_t ip_addr, std::vector<uint8_t> payload);
  std::vector<std::vector<uint8_t>> DequeueAllPacketsOnIP(uint32_t ip_addr);

  ARP(const uint8_t device_mac[6], uint32_t device_ip,
      uint64_t time_mac_expiration_s = 60 * 10)
      : device_ip(device_ip), time_mac_expiration_s(time_mac_expiration_s) {
    memcpy(this->device_mac, device_mac, sizeof(this->device_mac));
  }
  ARP(const uint8_t device_mac[6], char *device_ip,
      uint64_t time_mac_expiration_s = 60 * 10)
      : time_mac_expiration_s(time_mac_expiration_s) {
    memcpy(this->device_mac, device_mac, sizeof(this->device_mac));

    if (!decode_ip_address(device_ip, this->device_ip)) {
      printf("Invalid IP address\n");
    }
  }
};