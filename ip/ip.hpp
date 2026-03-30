#pragma once

#include <cstdint>
#include <unordered_map>
#include <header/header.hpp>
#include <settings/settings.hpp>
#include <vector>

struct ipv4_packet_t {
  ipv4_packet_header header;
  std::vector<uint8_t> data;

  std::vector<uint8_t> dump_network_packet();

  ipv4_packet_t(std::vector<uint8_t> raw);
  ipv4_packet_t(std::vector<uint8_t> payload,
                               ipv4_fragment_info_t fragment_info,
                               uint32_t destination, ipv4_settings_t &settings);
};

struct ipv4_packet_batch_t {
  std::vector<ipv4_packet_t> ipv4_packets;
  uint16_t packet_id;
  bool done = false;

  bool get_payload(std::vector<uint8_t> &merged_payload);

  bool add_packet(ipv4_packet_t packet);
};

class IPv4Sender {
private:
  ipv4_settings_t settings;

public:
  IPv4Sender(ipv4_settings_t &settings) : settings(settings) {}

  bool GeneratePackets(std::vector<uint8_t> &payload,
                       char destination[], ipv4_packet_batch_t &batch);
};

class IPv4Receiver {
private:
  ipv4_settings_t settings;
  std::unordered_map<uint16_t, ipv4_packet_batch_t> packets;
public:
  IPv4Receiver(ipv4_settings_t &settings) : settings(settings) {}
  void ReadPackets(std::vector<uint8_t> &data);

  std::vector<ipv4_packet_batch_t> PopFinishedBatch();
  void RemoveTimedOutBatches();

  ipv4_packet_batch_t RoutePacket(ipv4_packet_t packet, char destination[15]);
};