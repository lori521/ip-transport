#include "tcp_header.hpp"

// TODO: implement tcp_window_size dynamic algorithm -> later
// tcp header -> tcp header + data -> pseudo-header + tcp header + data -> checksum

/* TCP_PSEUDOHEADER */

// TODO: implement constructor for tcp pseudo-header without parameters
tcp_pseudoheader::tcp_pseudoheader() {
    memset(this, 0, sizeof(tcp_pseudoheader));
}

// // TODO: implement constructor for tcp pseudo-header with parameters
tcp_pseudoheader::tcp_pseudoheader(uint32_t source_ip, uint32_t destination_ip, uint16_t tcp_length) {
    this->source_address = source_ip;
    this->destination_address = destination_ip;
    this->tcp_length = tcp_length;
    this->zero = 0;
    // number used for TCP protocol
    this->PTCL = 6;
}

/* TCP_HEADER */
// TODO: implement constructor for tcp header without parameters
tcp_header::tcp_header() {
    memset(this, 0, sizeof(tcp_header));
}

// function to generate a random sequence number
uint32_t generate_random_sequence_number() {
    return rand();
}

// TODO: implement constructor for tcp header with parameters
tcp_header::tcp_header(uint16_t source_port, uint16_t destination_port) {
    this->source_port = source_port;
    this->destination_port = destination_port;
    this->sequence_number = generate_random_sequence_number();
    this->ack_number = 0;
    this->data_offset_and_reserved = 5;
    this->flags = 0;
    this->window = 65535;
    this->checksum = 0;
    this->urgent_pointer = 0;
    // what do i do with options?
}

/* TCP_PACKAGE */
// TODO: implement constructor for tcp package
tcp_package::tcp_package(tcp_pseudoheader pshdr, tcp_header hdr, char* new_payload) {
    this->tcp_hdr = hdr;
    this->payload = static_cast<char *>(calloc(PAYLOAD_LENGTH, sizeof(char)));
    memcpy(this->payload ,new_payload, sizeof(new_payload));
    // TODO: calculate checksum for whole package

}

// TODO: write check_sum algorithm -> modify with FEC for better transmission
uint16_t tcp_package::checksum(tcp_pseudoheader *pshdr_addr, tcp_package *package_addr, int packet_size) {
     uint32_t sum = 0;
    // loop through the pseudo-header and add to the sum
    int pshdr_size = sizeof(tcp_pseudoheader);

    while (pshdr_size > 1) {
        sum += (*reinterpret_cast<uint8_t*>(pshdr_addr))++;
        pshdr_size -= 2;
    }
    // no left-over byte because the number of bytes in this is even

    // loop through the package and add to the sum
    while (packet_size > 1) {
        sum += *package_addr++;
        packet_size -= 2;
    }

    // check if there is a left-over byte (odd number of bytes)
    if (packet_size > 0)
        // sort of padding
        sum += *reinterpret_cast<uint8_t*>(package_addr);

    // fold sum from uint32_t -> uint16_t
    while (sum >> 16) {
        sum = (sum & CHECK_SUM_MASK) + (sum >> 16);
    }

    uint16_t check_sum = ~sum;
    return check_sum;
}

int main() {
    return 0;
}