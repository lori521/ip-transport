#include "tcp_header.hpp"

// TODO: write decapsulate packet
// receive from network -> [ tcp_header | payload ] (20/max PAYLOAD_LENGTH bytes)
bool tcp_packet::decapsulate_package(tcp_pseudoheader *pshdr_addr, uint8_t *raw_buffer, uint16_t raw_buffer_length) {
    // checksum verification for received packet
    // get received checksum
    uint16_t old_checksum = *(uint16_t*)(raw_buffer + 16);
    // recalculate checksum for verification
    raw_buffer[16] = 0;
    raw_buffer[17] = 0;
    uint8_t *payload_addr = raw_buffer + sizeof(tcp_hdr);
    uint16_t payload_length = raw_buffer_length - sizeof(tcp_hdr);
    
    uint16_t new_checksum = this->tcp_hdr.caluculate_checksum(pshdr_addr, (tcp_header*)raw_buffer, payload_addr, payload_length);

    // check if old_checksum is the same as new_checksum
    if (new_checksum != old_checksum) {
        printf("checksum is not the same ... another try might suffice:))\n");
        return false;
    } 

    // variable to check if header could be read
    bool check;
    check = this->tcp_hdr.read_raw_header(raw_buffer);

    if (!check) {
        printf("could not read raw_buffer...try again buddy\n");
        return false;
    }
    
    // set checksum again
    this->tcp_hdr.set_checksum(new_checksum);
    
    // copy data inside raw_buffer into payload
    // update payload_length
    uint8_t  offset = this->tcp_hdr.get_data_offset() * 4;
    uint8_t  *payload_addr_with_offset  = raw_buffer + offset;
    uint16_t payload_length_with_offset = raw_buffer_length - offset;

    // manual garbage collector :))
    if (this->payload != nullptr) {
        free(this->payload);
        this->payload = nullptr;
    }
    
    if (payload_length_with_offset > 0) {
        this->payload = static_cast<uint8_t *>(calloc(payload_length_with_offset, sizeof(uint8_t)));
        if (this->payload == nullptr) {
            printf("could not allocate space for received payload :/\n");
            return false;
        }
        memcpy(this->payload, payload_addr_with_offset, payload_length_with_offset);
    }

    // set payload length
    this->payload_length = payload_length_with_offset;

    // all good :))
    return true;
}

// TODO: write encapsulate packet
uint8_t* tcp_packet::encapsulate_package(uint16_t &package_length) {
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
    if (this->payload != nullptr && this->payload_length > 0)
        memcpy(send_buffer + this->tcp_hdr.get_data_offset() * 4, this->payload, this->payload_length);

    return send_buffer;
}