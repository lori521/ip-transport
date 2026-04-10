#ifndef TCP_HPP
#define TCP_HPP

#include <stdint.h>
#include <unistd.h>
#include <iostream>
#include <arpa/inet.h>
#include <cstdlib>

using namespace std;

// payload and mask
#define PAYLOAD_LENGTH 65535
#define CHECK_SUM_MASK 0xFFFF

// flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
// OPTIONS_LENGTH -> size(Options) == (DOffset-5)*32
// PAYLOAD_LENGTH -> variable

// control_bits default values -> 0

class tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset_and_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    char options[];

public:
    tcp_header();
    tcp_header(uint16_t source_port, uint16_t destination_port);
} __attribute__((packed));

// IPv4 pseudo-header -> 96 bits(12 bytes)
// protection against misrouted segments
struct tcp_pseudoheader {
    uint32_t source_address;
    uint32_t destination_address;
    uint8_t zero;
    uint8_t PTCL;
    uint16_t tcp_length;

    tcp_pseudoheader();
    tcp_pseudoheader(uint32_t source_ip, uint32_t destination_ip, uint16_t tcp_length);
} __attribute__((packed));

// TCP Package -> IPv4 pseudo-header + TCP Header + payload
struct tcp_package {
    tcp_header tcp_hdr;
    uint8_t* payload;
    uint16_t payload_length;

    tcp_package();
    tcp_package(tcp_header* hdr, uint8_t* payload, uint16_t payload_length);

} __attribute__((packed));

uint16_t checksum(tcp_pseudoheader* pshdr, tcp_header* hdr, uint8_t* payload, uint16_t payload_length);
uint32_t generate_random_sequence_number();


#endif // TCP_HPP