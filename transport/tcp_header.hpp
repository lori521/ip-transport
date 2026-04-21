#ifndef TCP_HPP
#define TCP_HPP

#pragma once
#include <stdint.h>
#include <unistd.h>
#include <iostream>
#include <stdint.h>
#include <cstdlib>
#include  "../ip/header/header.hpp"
#include "../ip/ip.hpp"
#include "../ethernet/ethernet.hpp"
#include "utils/tcp_utils.hpp"
#include <sys/wait.h>
#include <unistd.h>
#include <random>

using namespace std;

// payload and mask
#define PAYLOAD_LENGTH 65535
#define CHECK_SUM_MASK 0xFFFF
#define MASK_FOR_OFFSET 0x0F

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

// default maximum segment size for TCP as 1460 bytes
#define MSS 1460

// ring buffer size for tcp
#define TCP_BUFFER_SIZE 4096

// enums for state machine
enum state {
    CLOSED,
    LISTEN,
    SYN_RECEIVED,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSING,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK
};

// send sequence variables
struct snd {
    // send unacknowledged
    uint32_t una;
    // send next
    uint32_t nxt;
    // send window
    uint16_t wnd;
    // send urgent pointer
    uint32_t up;
    // segment sequence number used for last window update
    uint32_t wl1;
    // segment acknowledgment number used for last window update
    uint32_t wl2;
    // initial send sequence number
    uint32_t iss;
};

// receive sequence variables
struct rcv {
    // receive next
    uint32_t nxt;
    // receive window
    uint16_t wnd;
    // receive urgent pointer
    uint32_t up;
    // initial receive sequence number
    uint32_t irs;
};

// current segment variables
struct seg {
    // segment sequence number
    uint32_t seq;
    // segment acknowledgment number
    uint32_t ack;
    // segment length
    uint32_t len;
    // segment window
    uint16_t wnd;
    // segment urgent pointer
    uint32_t up;
};


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

class tcp_header {
private:
    /* data */
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset_and_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    // char options[];

public:
    // functions to construct header
    tcp_header();
    tcp_header(uint16_t source_port, uint16_t destination_port);

    // auxiliar functions to modify header fields
    // setters
    void set_flag(uint8_t new_flag);
    void set_sequence(uint32_t new_seq_number);
    void set_ack_number(uint32_t new_ack_number);
    void set_source_port(uint16_t new_source_port);
    void set_destination_port(uint16_t new_destination_port);
    void set_checksum(int value);
    void set_window(uint16_t new_wnd_size);

    // getters
    uint32_t get_sequence();
    uint32_t get_ack_number();
    uint8_t get_flag();
    uint8_t get_data_offset();
    uint16_t get_checksum();
    uint16_t get_source_port();
    uint16_t get_destination_port();
    uint16_t get_window();
    
    // other auxiliar functions
    uint16_t caluculate_checksum(tcp_pseudoheader *pshdr_addr, tcp_header *hdr_addr, uint8_t *payload_addr, int payload_size);
    bool read_raw_header(uint8_t* raw_data);
} __attribute__((packed));

// TCP Packet -> TCP Header + payload
struct tcp_packet {
    tcp_header tcp_hdr;
    uint8_t* payload;
    uint16_t payload_length;

    // constructors
    tcp_packet();
    tcp_packet(tcp_pseudoheader pshdr, tcp_header hdr, uint8_t* new_payload, int payload_length);
    void free_package();

    // sending/receivind raw data 
    bool decapsulate_package(tcp_pseudoheader *pshdr_addr, uint8_t *raw_buffer, uint16_t raw_buffer_length);
    uint8_t* encapsulate_package(tcp_pseudoheader *pshdr_addr, uint16_t &package_length);
} __attribute__((packed));

class tcp_layer {
private:
    /* data */
    IPv4 &ipv4_layer;
    state current_state;

    // transmit/receive buffer
    uint8_t tx_buffer[TCP_BUFFER_SIZE] __attribute__((aligned(4)));
    uint8_t rx_buffer[TCP_BUFFER_SIZE] __attribute__((aligned(4)));

    // pointer for send packet which has not received an ack
    uint32_t tx_head = 0;
    // pointer to empty space left in tx_buffer
    uint32_t tx_tail = 0;


    // transmission control block (TCB)
    snd snd_vars;
    rcv rcv_vars;
    seg seg_vars;

public:
    tcp_layer(IPv4 &new_ipv4_layer);
    ~tcp_layer() {}


    // GETTER
    state get_state();
    // SETTER
    void set_state(state new_state);

    // 3 waay handshake to establish connection
    bool establish_connection_receiver(char*  dest_ip, uint16_t dest_port, uint16_t src_port);
    bool establish_connection_sender(char* dest_ip, uint16_t dest_port, uint16_t src_port);
    
    // 4 way handshake to finish onnection
    bool finish_connection_receiver(char *dest_ip, uint16_t dest_port, uint16_t src_port);
    bool finish_connection_sender(char* dest_ip, uint16_t dest_port, uint16_t src_port);

    // stock data in buffer
    bool write_data_in_buffer(uint8_t* payload, uint16_t payload_length);
    // send data 

};

uint32_t generate_random_sequence_number();
#endif // TCP_HPP
