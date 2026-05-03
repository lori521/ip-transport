#pragma once

#include "arp/arp.hpp"
#include "routing/routing.hpp"
#include <cstdint>
#include <header/header.hpp>
#include <set>
#include <settings/settings.hpp>
#include <unordered_map>
#include <vector>
struct ipv4_packet_t {
  ipv4_packet_header header;
  std::vector<uint8_t> data;

  std::vector<uint8_t> dump_network_packet();

  bool read_raw(std::vector<uint8_t> raw);

  ipv4_packet_t() = default;
  ipv4_packet_t(std::vector<uint8_t> payload,
                ipv4_fragment_info_t fragment_info, uint32_t destination,
                ipv4_settings_t &settings);
  ipv4_packet_t(std::vector<uint8_t> payload,
                ipv4_fragment_info_t fragment_info, uint32_t destination,
                ipv4_settings_t &settings, const ipv4_options_t &ip_options);
};

struct CompareByFragmentOffset {
  bool operator()(const ipv4_packet_t &a, const ipv4_packet_t &b) const {
    return a.header.fragment_offset < b.header.fragment_offset;
  }
};

struct ipv4_packet_batch_t {
  std::set<ipv4_packet_t, CompareByFragmentOffset> ipv4_packets;
  uint16_t packet_id;
  bool done = false;

  bool get_payload(std::vector<uint8_t> &merged_payload);

  bool add_packet(ipv4_packet_t packet);
};

class IPv4 {
private:
  IPv4Router &router;
  ARP &arp;
  ipv4_settings_t settings;
  std::unordered_map<uint16_t, ipv4_packet_batch_t> packets;

  bool ReadPackets(ipv4_packet_t packet);
  bool RedirectIPPacket(ipv4_packet_t packet);

  bool PopFinishedBatch(ipv4_packet_batch_t &finished);
  void RemoveTimedOutBatches();

  bool GeneratePackets(std::vector<uint8_t> &payload, uint32_t destination,
                       ipv4_packet_batch_t &batch);
  bool GeneratePackets(std::vector<uint8_t> &payload, uint32_t destination,
                       ipv4_packet_batch_t &batch,
                       const ipv4_options_t &options);
  bool HandleARP();

public:
  IPv4(ARP &arp, IPv4Router &router, const ipv4_settings_t &settings)
      : arp(arp), router(router), settings(settings) {}

  bool SendIPPacket(vector<uint8_t> &payload, char *destination);
  bool SendIPPacket(vector<uint8_t> &payload, uint32_t destination);
  bool ReadIPPacket(vector<uint8_t> &received_payload, char *source);

  // Support this for future use
  bool ReadIPPacket(vector<uint8_t> &received_payload,
                    ipv4_packet_header &header);
  uint32_t GetSourceAddress();
  void GetSourceAddress(char *address);
};
