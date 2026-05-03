#include "ethernet.hpp"

Ethernet::Ethernet(Manchester &m, const uint8_t *source_mac_address) : m(m) {
  memcpy(source_mac, source_mac_address, MAC_ADDRESS_LEN);
}

uint32_t Ethernet::calculate_fcs(const uint8_t *data, size_t length) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < length; i++) {
    uint8_t byte = data[i];
    for (int bit = 0; bit < 8; bit++) {
      bool bit_crc = (crc & 1) != 0;
      bool bit_data = (byte & (1 << bit)) != 0;
      crc = (crc >> 1) ^ ((bit_crc ^ bit_data) ? 0xEDB88320 : 0);
    }
  }
  return ~crc;
}

vector<uint8_t> Ethernet::eth_encap(const uint8_t *payload,
                                    uint32_t payload_len, EthernetType eth_type,
                                    uint8_t destination_mac[MAC_ADDRESS_LEN]) {
  const size_t total_frame_size = MAC_HEADER_LEN + payload_len + FCS_LEN;
  uint8_t frame[total_frame_size] = {0};

  // Current position tracker for frame construction
  size_t current_pos = 0;

  // Destination MAC
  memcpy(frame + current_pos, destination_mac, MAC_ADDRESS_LEN);
  current_pos += MAC_ADDRESS_LEN;

  // Source MAC
  memcpy(frame + current_pos, source_mac, MAC_ADDRESS_LEN);
  current_pos += MAC_ADDRESS_LEN;

  // EtherType
  memcpy(frame + current_pos, &eth_type, sizeof(eth_type));
  current_pos += sizeof(eth_type);

  // Payload
  memcpy(frame + current_pos, payload, payload_len);
  current_pos += payload_len;

  // FCS
  fcs = calculate_fcs(frame, MAC_HEADER_LEN + payload_len);
  memcpy(frame + current_pos, &fcs, sizeof(fcs));

  return vector<uint8_t>(frame, frame + sizeof(frame));
}

vector<uint8_t> Ethernet::eth_decap(uint8_t *frame, uint32_t frame_data_length,
                                    EthernetType *eth_type,
                                    uint8_t destination_mac[MAC_ADDRESS_LEN]) {
  if (frame_data_length < MAC_HEADER_LEN + FCS_LEN) {
    printf("Payload is too small\n");
    return {};
  }

  // Extract the received FCS
  uint32_t received_fcs;
  memcpy(&received_fcs, frame + frame_data_length - 4, sizeof(received_fcs));

  // Calculate the FCS
  uint32_t calculated_fcs = calculate_fcs(frame, frame_data_length - 4);

  // Compare FCS
  if (received_fcs != calculated_fcs) {
    printf("Frame Check Sequence (FCS) error!\n");
    return vector<uint8_t>();
  }

  // Compare EtherType
  if (eth_type != NULL) {
    memcpy(eth_type, frame + 2 * MAC_ADDRESS_LEN, sizeof(*eth_type));
  }

  // broadcast support
  uint8_t broadcast_mac_cmp[MAC_ADDRESS_LEN] = {0xFF, 0xFF, 0xFF,
                                                0xFF, 0xFF, 0xFF};

  if (memcmp(frame, source_mac, MAC_ADDRESS_LEN) != 0 &&
      memcmp(frame, broadcast_mac_cmp, MAC_ADDRESS_LEN) != 0) {
    printf("Destination MAC error!\n");
    return vector<uint8_t>();
  }

  if (destination_mac != NULL) {
    memcpy(destination_mac, frame + MAC_ADDRESS_LEN, MAC_ADDRESS_LEN);
  }

  return vector<uint8_t>(frame + MAC_HEADER_LEN, frame + frame_data_length - 4);
}

bool Ethernet::Read(std::vector<uint8_t> &payload,
                    uint8_t destination_mac[MAC_ADDRESS_LEN],
                    EthernetType *eth_type) {
  vector<uint8_t> raw;
  if (!this->m.Read(raw)) {
    return false;
  }

  payload = this->eth_decap(raw.data(), raw.size(), eth_type, destination_mac);
  if (payload.size() == 0) {
    return false;
  }

  return true;
}

bool Ethernet::Peek(std::vector<uint8_t> &payload,
                    uint8_t destination_mac[MAC_ADDRESS_LEN],
                    EthernetType *eth_type) {
  vector<uint8_t> raw;
  if (!this->m.Peek(raw)) {
    return false;
  }

  payload = this->eth_decap(raw.data(), raw.size(), eth_type, destination_mac);
  if (payload.size() == 0) {
    return false;
  }

  return true;
}

bool Ethernet::Send(std::vector<uint8_t> payload,
                    uint8_t destination_mac[MAC_ADDRESS_LEN],
                    EthernetType eth_type) {
  vector<uint8_t> raw = this->eth_encap(payload.data(), payload.size(),
                                        eth_type, destination_mac);

  if (!this->m.Send(raw)) {
    return false;
  }

  return true;
}