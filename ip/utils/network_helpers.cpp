#include "utils.h"
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

void push_uint32_n(std::vector<uint8_t> &data, uint16_t payload) {
  data.push_back(payload & 0b11111111);
  data.push_back(((payload >> 8) & 0b11111111));
  data.push_back(((payload >> 16) & 0b11111111));
  data.push_back(payload >> 24);
}

uint32_t read_uint32_n(std::vector<uint8_t> &data, int idx) {
  uint32_t d_word = (((uint32_t)data[idx + 3]) << 24) |
                    (((uint32_t)data[idx + 2]) << 16) |
                    (((uint32_t)data[idx + 1]) << 8) | ((uint32_t)data[idx]);
  return d_word;
}

// This can throw invalid_argument if addr is formatted wrong
uint32_t decode_ip_address(char addr[15]) {
  char *part = strtok(addr, ".");
  for (int i = 0; i < 4; i++) {
    uint8_t parsed_byte = std::stoi(part);
    part = strtok(NULL, ".");
    if (part == NULL) {
      throw std::invalid_argument("Address has invalid format");
    }
  }
}