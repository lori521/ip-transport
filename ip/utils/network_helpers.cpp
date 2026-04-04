#include "utils/utils.hpp"
#include <cstdint>
#include <cstring>
#include <stdexcept>

// Helpers
void push_uint16_n(std::vector<uint8_t> &data, uint16_t payload) {
  data.push_back(payload & 0b11111111);
  data.push_back(payload >> 8);
}

uint16_t read_uint16_n(std::vector<uint8_t> &data, size_t idx) {
  uint16_t word = (((uint16_t)data[idx + 1]) << 8) | ((uint16_t)data[idx]);
  return word;
}

void push_uint32_n(std::vector<uint8_t> &data, uint32_t payload) {
  data.push_back(payload >> 24);
  data.push_back(((payload >> 16) & 0b11111111));
  data.push_back(((payload >> 8) & 0b11111111));
  data.push_back(payload & 0b11111111);
}

uint32_t read_uint32_n(std::vector<uint8_t> &data, int idx) {
  uint32_t d_word =
      (((uint32_t)data[idx]) << 24) | (((uint32_t)data[idx + 1]) << 16) |
      (((uint32_t)data[idx + 2]) << 8) | ((uint32_t)data[idx + 3]);
  return d_word;
}

bool decode_ip_address(const char *addr, uint32_t &ip_encoded) {
  ip_encoded = 0;

  int read = sscanf(addr, "%hhu.%hhu.%hhu.%hhu", ((uint8_t *)&ip_encoded) + 3,
                    ((uint8_t *)&ip_encoded) + 2, ((uint8_t *)&ip_encoded) + 1,
                    ((uint8_t *)&ip_encoded));
  if (read != 4) {
    printf("Could not read address\n");
    return false;
  }

  return true;
}

void encode_ip_address(uint32_t ip, char *buff) {
  sprintf(buff, "%hhu.%hhu.%hhu.%hhu", ip >> 24, (ip >> 16) & 0b11111111,
          (ip >> 8) & 0b11111111, ip & 0b11111111);
}