#ifndef PICO_PRJ_UTILS_H
#define PICO_PRJ_UTILS_H
#include <cstdint>
#include <vector>

void push_uint16_n(std::vector<uint8_t> &data, uint16_t payload);
uint16_t read_uint16_n(std::vector<uint8_t> &data, size_t idx);
void push_uint32_n(std::vector<uint8_t> &data, uint16_t payload);
uint32_t read_uint32_n(std::vector<uint8_t> &data, int idx);

#endif //PICO_PRJ_UTILS_H