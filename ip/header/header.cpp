#include "header.hpp"
#include "utils/utils.hpp"
#include <stdexcept>
// IPv4 Options

// Dump data inside options as bytes
std::vector<uint8_t> ipv4_options_t::dump_options() { return this->data; }

// Read data inside options
ipv4_options_t::ipv4_options_t(std::vector<uint8_t> raw_data) {
  this->data = std::move(raw_data);
}

// Gets the options size in bytes
size_t ipv4_options_t::size() { return this->data.size(); }

// IPv4 Header

// Dumps Ipv4 header as bytes in network endianess
std::vector<uint8_t> ipv4_packet_header::dump_network_header() {
  std::vector<uint8_t> network_payload;

  // Copy version and header_length
  network_payload.push_back(((version & 0b1111) << 4) |
                            (header_length & 0b1111));

  // Copy service type
  network_payload.push_back(service_type);

  // Copy total_length in network order
  push_uint16_n(network_payload, total_length);

  // Copy packet id in network order
  push_uint16_n(network_payload, packet_id);

  // Copy flag + fragment_offset in network order
  uint16_t flags_fragment_word =
      ((this->flags & 0b111) << 13) | (this->fragment_offset & 0b1111111111111);
  push_uint16_n(network_payload, flags_fragment_word);

  // Copy ttl
  network_payload.push_back(ttl);

  // Copy protocol
  network_payload.push_back(protocol);

  // Copy check sum
  push_uint16_n(network_payload, header_check_sum);

  // Copy addreses
  push_uint32_n(network_payload, source_ip_address);
  push_uint32_n(network_payload, destination_ip_address);

  // Copy options
  std::vector<uint8_t> options_payload = this->options.dump_options();
  network_payload.insert(network_payload.end(), options_payload.begin(),
                         options_payload.end());

  return network_payload;
}

// Read header from raw data
ipv4_packet_header::ipv4_packet_header(std::vector<uint8_t> raw) {
  // Copy fixed part
  size_t idx = 0;

  // Copy version and header_length
  uint8_t byte = raw[idx++];
  version = byte >> 4;
  header_length = byte & 0b1111;

  printf("version = %hhu\n", version);

  // Copy service type
  service_type = raw[idx++];

  // Copy total_length
  total_length = read_uint16_n(raw, idx);
  idx += 2;

  // Copy packet id
  packet_id = read_uint16_n(raw, idx);
  idx += 2;

  // Copy flags
  uint16_t flags_fragment_word = read_uint16_n(raw, idx);
  idx += 2;

  flags = flags_fragment_word >> 13;
  fragment_offset = flags_fragment_word & 0b1111111111111;

  // Copy ttl
  ttl = raw[idx++];

  // Copy protocol
  protocol = raw[idx++];

  // Copy checksum
  header_check_sum = read_uint16_n(raw, idx);
  idx += 2;

  // Copy adresses
  source_ip_address = read_uint32_n(raw, idx);
  idx += 4;

  destination_ip_address = read_uint32_n(raw, idx);
  idx += 4;

  // Copy options
  size_t options_len = this->header_length - FIXED_PART_HEADER_SIZE;
  if (options_len > 40) {
    std::printf("Options cannot have length > 40\n");
    return;
  }

  this->options = ipv4_options_t(std::vector<uint8_t>(
      raw.begin() + FIXED_PART_HEADER_SIZE, raw.begin() + this->header_length));
}

// Create new IPv4 packet header
ipv4_packet_header::ipv4_packet_header(uint16_t payload_size,
                                       ipv4_fragment_info_t fragment_info,
                                       uint32_t destination,
                                       ipv4_settings_t &settings) {
  this->version = 4;
  this->header_length = FIXED_PART_HEADER_SIZE + settings.options.size();
  this->service_type = settings.service_type;
  this->total_length = payload_size + this->header_length;

  if (settings.allow_fragmentation && fragment_info.is_fragmented) {
    this->packet_id = fragment_info.fragment_id;
    this->fragment_offset = fragment_info.fragment_offset;
    if (!fragment_info.is_last) {
      this->flags = MORE_FRAGMENTS;
    }
  } else {
    this->flags = settings.allow_fragmentation ? 0 : DO_NOT_FRAGMENT;
  }

  this->ttl = settings.ttl;
  this->protocol = settings.protocol;
  this->source_ip_address = settings.device_ip_address;
  this->destination_ip_address = destination;
  // Checksum is calculated at the end
  this->header_check_sum = 0;
}

void ipv4_packet_header::debug() {
  printf("Header: \n");
  printf("-version = %u\n", this->version);
  printf("-header_len = %u\n", this->header_length);
  printf("-service type = %u\n", this->service_type);
  printf("-total length = %u\n", this->total_length);
  printf("-packet id = %u\n", this->packet_id);
  printf("-source_addr = %u\n", this->source_ip_address);
  printf("-destination_addr = %u\n", this->destination_ip_address);
}
