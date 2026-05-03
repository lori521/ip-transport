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
size_t ipv4_options_t::size() const { return this->data.size(); }

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

  // Add padding to 4 byte allignment
  while (network_payload.size() < (this->header_length << 2)) {
    network_payload.push_back(0);
  }
  return network_payload;
}

// Read header from raw data
bool ipv4_packet_header::read_raw(std::vector<uint8_t> raw) {
  if (raw.size() == 0) {
    // I need one byte
    printf("Empty payload in header parsing\n");
    return false;
  }

  // Copy fixed part
  size_t idx = 0;

  // Copy version and header_length
  uint8_t byte = raw[idx++];
  version = byte >> 4;

  header_length = byte & 0b1111;

  if (raw.size() < (header_length << 2)) {
    printf("Raw data is too small\n");
    return false;
  }

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
  size_t header_length_bytes = this->header_length << 2;
  size_t options_len = header_length_bytes - FIXED_PART_HEADER_SIZE;
  if (options_len > 40) {
    std::printf("Options cannot have length > 40\n");
    return false;
  }

  this->options = ipv4_options_t(std::vector<uint8_t>(
      raw.begin() + FIXED_PART_HEADER_SIZE, raw.begin() + header_length_bytes));

  // Test checksum
  // destination_ip_address++;

  if (header_check_sum != calculate_checksum()) {
    printf("IP header checksum does not match\n");
    return false;
  }
  return true;
}

// Create new IPv4 packet header
ipv4_packet_header::ipv4_packet_header(uint16_t payload_size,
                                       ipv4_fragment_info_t fragment_info,
                                       uint32_t destination,
                                       ipv4_settings_t &settings,
                                       const ipv4_options_t &options) {

  this->version = 4;
  this->options = options;

  size_t aligned_options_size = (((this->options.size() + 3) >> 2) << 2);
  this->header_length = (FIXED_PART_HEADER_SIZE + aligned_options_size) >> 2;

  this->service_type = settings.service_type;
  this->total_length = payload_size + (this->header_length << 2);

  this->packet_id = fragment_info.fragment_id;
  this->fragment_offset = fragment_info.fragment_offset;
  if (settings.allow_fragmentation && fragment_info.is_fragmented &&
      !fragment_info.is_last) {
    this->flags = MORE_FRAGMENTS;
  } else {
    this->flags = settings.allow_fragmentation ? 0 : DO_NOT_FRAGMENT;
  }

  this->ttl = settings.ttl;
  this->protocol = settings.protocol;
  this->source_ip_address = settings.device_ip_address;
  this->destination_ip_address = destination;
  this->header_check_sum = calculate_checksum();
}
ipv4_packet_header::ipv4_packet_header(uint16_t payload_size,
                                       ipv4_fragment_info_t fragment_info,
                                       uint32_t destination,
                                       ipv4_settings_t &settings)
    : ipv4_packet_header(payload_size, fragment_info, destination, settings,
                         ipv4_options_t()) {}
uint16_t ipv4_packet_header::calculate_checksum() {
  uint16_t preserve_checksum = this->header_check_sum;
  this->header_check_sum = 0;

  std::vector<uint8_t> bytes = this->dump_network_header();
  if ((bytes.size() & 1) == 1) {
    bytes.push_back(0);
  }

  uint32_t sum = 0;
  for (int i = 0; i < bytes.size(); i += 2) {
    uint16_t word = read_uint16_n(bytes, i);
    sum += word;
    sum = (sum & 0b1111111111111111) + (sum >> 16);
  }

  this->header_check_sum = preserve_checksum;
  return (~sum) & 0b1111111111111111;
}
void ipv4_packet_header::redirect() {
  this->ttl--;
  this->header_check_sum = this->calculate_checksum();
}

void ipv4_packet_header::debug() {
  printf("Header: \n");
  printf("-version = %u\n", this->version);
  printf("-header_len = %u\n", this->header_length);
  printf("-service type = %u\n", this->service_type);
  printf("-total length = %u\n", this->total_length);
  printf("-packet id = %u\n", this->packet_id);
  printf("-fragment_offset = %u\n", this->fragment_offset);
  printf("-do_not_fragment = %b\n", (this->flags & DO_NOT_FRAGMENT) != 0);
  printf("-more_fragments = %b\n", (this->flags & MORE_FRAGMENTS) != 0);
  printf("-source_addr = %u\n", this->source_ip_address);
  printf("-destination_addr = %u\n", this->destination_ip_address);
}
