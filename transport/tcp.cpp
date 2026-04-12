#pragma once
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
    return static_cast<uint32_t>(rand());
}

// TODO: implement constructor for tcp header with parameters
tcp_header::tcp_header(uint16_t source_port, uint16_t destination_port) {
    this->source_port = htons(source_port);
    this->destination_port = htons(destination_port);
    this->sequence_number = htonl(generate_random_sequence_number());
    this->ack_number = htonl(0);
    this->data_offset_and_reserved = (5 << 4);
    this->flags = 0;
    this->window = htons(65535);
    // IMPORTANT -> checksum set to 0
    this->checksum = 0;
    this->urgent_pointer = htons(0);
    // what do i do with options?
}

// TODO: implement function to set flag into the header
void tcp_header::set_flag(uint8_t new_flag) {
    this->flags |= new_flag;
}

// TODO: implement function to find data offset
uint8_t tcp_header::get_data_offset() {
    return (this->data_offset_and_reserved >> 4) & MASK_FOR_OFFSET;
}

// TODO: implement get/set method for checksum
uint16_t tcp_header::get_checksum() {
    return this->checksum;
}

void tcp_header::set_checksum(int value) {
    this->checksum = value;
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
tcp_package::tcp_package() {}

// TODO: implement constructor for tcp package with parameters
tcp_package::tcp_package(tcp_pseudoheader pshdr, tcp_header hdr, uint8_t* new_payload, int payload_length) {
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
    memcpy(this->payload, new_payload, copy_payload_length);

    // calculate checksum for whole package
    this->tcp_hdr.set_checksum(0);

    uint16_t new_checksum = this->tcp_hdr.caluculate_checksum(&pshdr, &this->tcp_hdr, this->payload, copy_payload_length);
    this->tcp_hdr.set_checksum(new_checksum);
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

void tcp_package::free_package() {
    if (this->payload != nullptr)
        free(this->payload);
}

// TODO: write decapsulate packet
// receive from network -> [ tcp_header | payload ] (20/max PAYLOAD_LENGTH bytes)
bool tcp_package::decapsulate_package(tcp_pseudoheader *pshdr_addr, uint8_t *raw_buffer, uint16_t raw_buffer_length) {
    // variable to check if header could be read
    bool check;
    check = this->tcp_hdr.read_raw_header(raw_buffer);

    if (!check) {
        printf("could not read raw_buffer...try again buddy\n");
        return false;
    }

    // checksum verification for received packet
    // get received checksum
    uint16_t old_checksum = this->tcp_hdr.get_checksum();
    // recalculate checksum for verification
    this->tcp_hdr.set_checksum(0);
    uint8_t *payload_addr = raw_buffer + sizeof(tcp_hdr);
    uint16_t payload_length = raw_buffer_length - sizeof(tcp_hdr);
    
    uint16_t new_checksum = this->tcp_hdr.caluculate_checksum(pshdr_addr, &this->tcp_hdr, payload_addr, payload_length);

    // check if old_checksum is the same as new_checksum
    if (new_checksum != old_checksum) {
        printf("checksum is not the same ... another try might suffice:))\n");
        return false;
    } else {
        this->tcp_hdr.set_checksum(new_checksum);
    }
    
    // copy data inside raw_buffer into payload
    // update payload_length
    uint8_t  offset = this->tcp_hdr.get_data_offset() * 4;
    uint8_t  *payload_addr_with_offset  = raw_buffer + offset;
    uint16_t payload_length_with_offset = raw_buffer_length - offset;
    this->payload = static_cast<uint8_t *>(calloc(payload_length_with_offset, sizeof(uint8_t)));
    if (this->payload == nullptr) {
        printf("could not allocate space for received payload :/\n");
        return false;
    }
    memcpy(this->payload, payload_addr_with_offset, payload_length_with_offset);

    // set payload length
    this->payload_length = payload_length_with_offset;

    // all good :))
    return true;
}

// TODO: write encapsulate packet
uint8_t* tcp_package::encapsulate_package(uint16_t &package_length) {
    // set package_length
    package_length = this->tcp_hdr.get_data_offset() * 4 + this->payload_length;

    // allocate send_buffer(boy goin up the wire)
    uint8_t *send_buffer = static_cast<uint8_t *>(calloc(package_length, sizeof(uint8_t)));
    if (send_buffer == nullptr) {
        printf("could not allocate space for send_buffer :/\n");
        return nullptr;
    }

    // copy header in send_buffer
    memcpy(send_buffer, &this->tcp_hdr, sizeof(tcp_hdr));

    // copy payload
    memcpy(send_buffer + this->tcp_hdr.get_data_offset() * 4, this->payload, this->payload_length);

    return send_buffer;
}

int main() {

    return 0;
}