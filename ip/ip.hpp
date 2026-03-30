#pragma once

#include <cstdint>
#include <header/header.hpp>
#include <settings/settings.hpp>
#include <vector>

struct ipv4_packet_t {
  ipv4_packet_header header;
  std::vector<uint8_t> data;

  std::vector<uint8_t> dump_network_packet();

  ipv4_packet_t(std::vector<uint8_t> raw);
  ipv4_packet_t::ipv4_packet_t(std::vector<uint8_t> payload,
                               ipv4_fragment_info_t fragment_info,
                               uint32_t destination, ipv4_settings_t &settings);
};

struct ipv4_packet_batch_t {
  std::vector<ipv4_packet_t> ipv4_packets;
  uint16_t packet_id;
  bool done = false;

  std::vector<uint8_t> get_payload();
  void add_packet(ipv4_packet_t packet);
  std::vector<uint8_t> get_payload();
};

class IPv4 {
private:
  ipv4_settings_t settings;

public:
  IPv4(ipv4_settings_t &settings) : settings(settings) {}

  ipv4_packet_batch_t GeneratePackets(std::vector<uint8_t> &data,
                                      char destination[15]);
  void ReadPackets(std::vector<uint8_t> &data, ipv4_packet_batch_t &batch);
  ipv4_packet_batch_t RoutePacket(ipv4_packet_t packet, char destination[15]);
};
