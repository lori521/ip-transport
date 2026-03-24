#include "tcp_header.hpp"

#include "tcp.hpp"
#include <cstring>

// TODO: implement tcp_window_size dynamic algorithm
// tcp header -> tcp header + data -> pseudo-header + tcp header + data -> checksum

// TODO: implement constructor for tcp pseudo-header
tcp_pseudoheader::tcp_pseudoheader(const char* source_ip_address , const char* destination_ip_address, uint8_t PTCL) {
    memcpy(this->source_address, source_ip_address, sizeof(source_ip_address));
    memcpy(this->destination_address, destination_ip_address, sizeof(destination_ip_address));
    memset(this->zero,0, sizeof(zero));
    this->PTCL = PTCL;
}

// TODO: implement constructor for tcp header
tcp_header::tcp_header(uint16_t sp, uint16_t dp) {
    memcpy(this->source_port, sp, sizeof(sp));
    memcpy(this->destination_port, dp, sizeof(dp));
    this->sequence_number = rand();
    this->ack_number = 0;
    this->data_offset = 5;
    this->reserved = 0;
    // switch with algorithm
    this->window = 20000;
    this->checksum = 0;
    this->urgent_pointer = 0;
}

// TODO: implement constructor for tcp package
tcp_package::tcp_package(tcp_pseudoheader pshdr, tcp_header hdr, char* new_payload) {
    this->speudo_hdr = pshdr;
    this->tcp_hdr = hdr;
    this->payload = static_cast<char *>(calloc(PAYLOAD_LENGTH, sizeof(char)));
    this->payload = new_payload;
    // TODO: calculate checksum for whole package
}


int main() {
    return 0;
}