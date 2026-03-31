#pragma once
#include "utils/utils.hpp"
#include <cstdint>
#include <vector>

void push_uint16_n(std::vector<uint8_t> &data, uint16_t payload);
uint16_t read_uint16_n(std::vector<uint8_t> &data, size_t idx);
void push_uint32_n(std::vector<uint8_t> &data, uint32_t payload);
uint32_t read_uint32_n(std::vector<uint8_t> &data, int idx);
bool decode_ip_address(const char *addr, uint32_t &ip_encoded);