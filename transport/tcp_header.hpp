#ifndef TCP_HPP
#define TCP_HPP

#include <stdint.h>
#include <unistd.h>
#include <iostream>

using namespace std;

#define PORT_LENGTH 16
#define SEQUENCE_LENGTH 32
#define ACK_NUMBER_LENGTH 32
#define OFFSET_LENGTH 4
#define RESERVED 4
#define WINDOW_LENGTH 16
#define CHECKSUM_LENGTH 16
#define URGENT_POINTER_LENGTH 16
#define PAYLOAD_LENGTH 65535
// #define OPTIONS_LENGTH -> size(Options) == (DOffset-5)*32
// #define DATA_LENGTH -> variable

struct control_bits_t {
    uint8_t CWR : 1 = 0;
    uint8_t ECE : 1 = 0;
    uint8_t URG : 1 = 0;
    uint8_t ACK : 1 = 0;
    uint8_t PSH : 1 = 0;
    uint8_t PST : 1 = 0;
    uint8_t SYN : 1 = 0;
    uint8_t FIN : 1 = 0;
};

class tcp_header {
    uint16_t source_port : PORT_LENGTH;
    uint16_t destination_port : PORT_LENGTH;
    uint32_t sequence_number : SEQUENCE_LENGTH;
    uint32_t ack_number : ACK_NUMBER_LENGTH;
    uint8_t data_offset : OFFSET_LENGTH;
    uint8_t reserved : RESERVED;
    control_bits_t control_bits;
    uint16_t window : WINDOW_LENGTH;
    uint16_t checksum : CHECKSUM_LENGTH;
    uint16_t urgent_pointer : URGENT_POINTER_LENGTH = 0;
    char options[];

public:
    tcp_header();
};

// IPv4 pseudo-header -> 96 bits
// protection against misrouted segments
struct tcp_pseudoheader {
    uint32_t source_address : 32;
    uint32_t destination_address : 32;
    uint8_t zero : 8;
    uint8_t PTCL : 8;
    uint16_t tcp_length : 16;

    tcp_pseudoheader();
};

struct tcp_package {
    tcp_pseudoheader speudo_hdr;
    tcp_header tcp_hdr;
    char* payload;

    tcp_package();
};








#endif // TCP_HPP