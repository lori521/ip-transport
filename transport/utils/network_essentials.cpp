#include "tcp_utils.hpp"


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