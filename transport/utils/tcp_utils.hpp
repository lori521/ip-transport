#ifndef NETWORK_ESSENTIALS_HPP
#define NETWORK_ESSENTIALS_HPP

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdio>

// Byte order macros for Pico
#define htons(x) ((uint16_t)((((uint16_t)(x) & 0x00ff) << 8) | (((uint16_t)(x) & 0xff00) >> 8)))
#define htonl(x) ((uint32_t)((((uint32_t)(x) & 0x000000ff) << 24) | (((uint32_t)(x) & 0x0000ff00) << 8) | \
                             (((uint32_t)(x) & 0x00ff0000) >> 8) | (((uint32_t)(x) & 0xff000000) >> 24)))
#define ntohs(x) htons(x)
#define ntohl(x) htonl(x)

static inline uint32_t inet_addr(const char* addr) {
    uint32_t ip_encoded = 0;

    int read = sscanf(addr, "%hhu.%hhu.%hhu.%hhu", 
                      ((uint8_t *)&ip_encoded) + 3,
                      ((uint8_t *)&ip_encoded) + 2, 
                      ((uint8_t *)&ip_encoded) + 1,
                      ((uint8_t *)&ip_encoded));
                      
    if (read != 4) return 0;
    return ip_encoded;
}

#endif