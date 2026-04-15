#include "tcp_header.hpp"

// TODO: implement tcp_window_size dynamic algorithm -> later
// tcp header -> tcp header + data -> pseudo-header + tcp header + data -> checksum

/* --------------------- TCP_PSEUDOHEADER ---------------------------- */

// TODO: implement constructor for tcp pseudo-header without parameters
tcp_pseudoheader::tcp_pseudoheader() {
    memset(this, 0, sizeof(tcp_pseudoheader));
}

// // TODO: implement constructor for tcp pseudo-header with parameters
tcp_pseudoheader::tcp_pseudoheader(uint32_t source_ip, uint32_t destination_ip, uint16_t tcp_length) {
    this->source_address = source_ip;
    this->destination_address = destination_ip;
    this->tcp_length = htons(tcp_length);
    this->zero = 0;
    // number used for TCP protocol
    this->PTCL = 6;
}

/* ----------------------------- TCP_HEADER -------------------------------- */
// TODO: implement constructor for tcp header without parameters
tcp_header::tcp_header() {
    memset(this, 0, sizeof(tcp_header));
}

// function to generate a random sequence number
uint32_t generate_random_sequence_number() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> next_seq(0, 4294967295U);
    uint32_t initial_sequence_number = next_seq(gen);
    return initial_sequence_number;
}

// TODO: implement constructor for tcp header with parameters
tcp_header::tcp_header(uint16_t source_port, uint16_t destination_port) {
    this->source_port = source_port;
    this->destination_port = destination_port;
    this->sequence_number = generate_random_sequence_number();
    this->ack_number = 0;
    this->data_offset_and_reserved = (5 << 4);
    this->flags = 0;
    this->window = 65535;
    // IMPORTANT -> checksum set to 0
    this->checksum = 0;
    this->urgent_pointer = 0;
    // what do i do with options?
}

// SETTERS
// TODO: implement function to set flag into the header
void tcp_header::set_flag(uint8_t new_flag) {
    this->flags |= new_flag;
}

// TODO: implement function to set new ack number
void tcp_header::set_ack_number(uint32_t new_ack_number) {
    this->ack_number = new_ack_number;
}

// TODO: implement function to set new seq number
void tcp_header::set_sequence(uint32_t new_seq_number) {
    this->sequence_number = new_seq_number;
}

// TODO: implement function to set checksum 
void tcp_header::set_checksum(int value) {
    this->checksum = value;
}

// TODO: implement function to set source port
void tcp_header::set_source_port(uint16_t new_source_port) {
    this->source_port = new_source_port;
}

// TODO: implement function to set destination port
void tcp_header::set_destination_port(uint16_t new_destination_port) {
    this->destination_port = new_destination_port;
}

// TODO: implement function to set window
void tcp_header::set_window(uint16_t new_wnd_size) {
    this->window = new_wnd_size;
}

// GETTERS 
// TODO: implement function to get sequence number
uint32_t tcp_header::get_sequence() {
    return this->sequence_number;
}

uint32_t tcp_header::get_ack_number() {
    return this->ack_number;
}

// TODO: implement function to get flags
uint8_t tcp_header::get_flag() {
    return this->flags;
}

// TODO: implement function to find data offset
uint8_t tcp_header::get_data_offset() {
    return (this->data_offset_and_reserved >> 4) & MASK_FOR_OFFSET;
}

// TODO: implement get method for checksum
uint16_t tcp_header::get_checksum() {
    return this->checksum;
}

// TODO: implement function to get source port
uint16_t tcp_header::get_source_port() {
    return this->source_port;
}

 // TODO: implement function to get destination port
uint16_t tcp_header::get_destination_port() {
    return this->destination_port;
}

// TODO: implement function to get window
uint16_t tcp_header::get_window() {
    return this->window;
}

// TODO: write helper function to read bytes sent
bool tcp_header::read_raw_header(uint8_t* raw_data) {
    // sanity chheck
    if (raw_data == nullptr) {
        printf("could not get raw_data\n");
        return false;
    }

    // copy data
    // IMPORTANT -> it is in network order
    memcpy(this, raw_data, sizeof(tcp_header));

    // convert network order to host order
    this->source_port = ntohs(this->source_port);
    this->destination_port = ntohs(this->destination_port);
    this->sequence_number = ntohl(this->sequence_number);
    this->ack_number = ntohl(this->ack_number);
    this->window = ntohs(this->window);
    this->checksum = ntohs(this->checksum);
    this->urgent_pointer = ntohs(this->urgent_pointer);

    return true;
}

/* ---------------------------------- TCP_PACKAGE ------------------------------------- */
// TODO: implement constructor for tcp package without parameters
tcp_packet::tcp_packet() {
    this->payload = nullptr;
    this->payload_length = 0;
}

// TODO: implement constructor for tcp package with parameters
tcp_packet::tcp_packet(tcp_pseudoheader pshdr, tcp_header hdr, uint8_t* new_payload, int payload_length) {
    // add header to package
    this->tcp_hdr = hdr;

    // add payload size
    this->payload_length = payload_length;

    // allocate space for payload
    this->payload = static_cast<uint8_t *>(calloc(PAYLOAD_LENGTH, sizeof(uint8_t)));

    // check payload length to put inside packet
    int copy_payload_length = 0;
    if (payload_length < PAYLOAD_LENGTH)
        copy_payload_length = payload_length;
    else
        copy_payload_length = PAYLOAD_LENGTH;

    if (new_payload != nullptr && copy_payload_length > 0)
        memcpy(this->payload, new_payload, copy_payload_length);
}

// TODO: write check_sum algorithm -> modify with FEC for better transmission
uint16_t tcp_header::caluculate_checksum(tcp_pseudoheader *pshdr_addr, tcp_header *hdr_addr, uint8_t *payload_addr, int payload_size) {
    uint32_t sum = 0;

    // loop through the pseudo-header first and add to the sum
    uint16_t *pshdr_ptr = reinterpret_cast<uint16_t*>(pshdr_addr);
    int pshdr_size = sizeof(tcp_pseudoheader);

    while (pshdr_size > 1) {
        sum += *pshdr_ptr++;
        pshdr_size -= 2;
    }
    // no left-over byte because the number of bytes in this is even

    // loop through the tcp header and add to the sum
    uint16_t *hdr_ptr = reinterpret_cast<uint16_t*>(hdr_addr);
    int hdr_size = sizeof(tcp_header);

    while (hdr_size > 1) {
        sum += *hdr_ptr++;
        hdr_size -= 2;
    }

    // loop through the tcp payload and add to the sum
    uint16_t *payload_ptr = reinterpret_cast<uint16_t*>(payload_addr);

    while (payload_size > 1) {
        sum += *payload_ptr++;
        payload_size -= 2;
    }

    // check if there is a left-over byte (odd number of bytes)
    if (payload_size > 0)
        // sort of padding
            sum += static_cast<uint32_t>(*(reinterpret_cast<uint8_t*>(payload_ptr))) << 8;

    // fold sum from uint32_t -> uint16_t
    while (sum >> 16) {
        sum = (sum & CHECK_SUM_MASK) + (sum >> 16);
    }

    return ~sum;
}

void tcp_packet::free_package() {
    if (this->payload != nullptr) {
        free(this->payload);
        this->payload = nullptr;
    }
}
