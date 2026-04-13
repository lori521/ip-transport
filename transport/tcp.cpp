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

// TODO: implement function to set new ack number
void tcp_header::set_ack_number(uint32_t new_ack_number) {
    this->ack_number = htonl(new_ack_number);
}

// TODO: implement function to set new seq number
void tcp_header::set_sequence(uint32_t new_seq_number) {
    this->sequence_number = htonl(new_seq_number);
}

// TODO: implement function to get sequence number
uint32_t tcp_header::get_sequence() {
    return this->sequence_number;
}

// TODO: implement function to get flags
uint8_t tcp_header::get_flag() {
    return this->flags;
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
tcp_packet::tcp_packet() {}

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

    // calculate checksum for whole package
    this->tcp_hdr.set_checksum(0);

    uint16_t new_checksum = this->tcp_hdr.caluculate_checksum(&pshdr, &this->tcp_hdr, this->payload, copy_payload_length);
    this->tcp_hdr.set_checksum(htons(new_checksum));
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
    if (this->payload != nullptr)
        free(this->payload);
}

// TODO: write decapsulate packet
// receive from network -> [ tcp_header | payload ] (20/max PAYLOAD_LENGTH bytes)
bool tcp_packet::decapsulate_package(tcp_pseudoheader *pshdr_addr, uint8_t *raw_buffer, uint16_t raw_buffer_length) {
    // checksum verification for received packet
    // get received checksum
    uint16_t old_checksum = ntohs(*(uint16_t*)(raw_buffer + 16));
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
    memcpy(send_buffer + this->tcp_hdr.get_data_offset() * 4, this->payload, this->payload_length);

    return send_buffer;
}

/* ---------- 3 way handshake to open connection --------------- */
// establish_connetion from server/receiver's perspective
// -> receive SYN(syn#A)
// -> send ACK-SYN (ack#B, syn#A + 1) 
// -> receive ACK (ack#B + 1)
// -> print connection established server for debugging
bool tcp_packet::establish_connection_receiver(int socketfd, tcp_pseudoheader *pshdr_addr, uint16_t dest_port, uint16_t src_port) {
    uint8_t *temp_buffer = static_cast<uint8_t *>(calloc(PAYLOAD_LENGTH + sizeof(tcp_header), sizeof(uint8_t)));

    // wait to receive from sender first
    struct sockaddr_in sender_addr;
    socklen_t sender_length = sizeof(sender_addr);

    // hopefully receiving syn
    // printf("[SERVER] waiting for SYN...\n"); fflush(stdout);
    int rc = recvfrom(socketfd, temp_buffer, PAYLOAD_LENGTH + sizeof(tcp_header), 0, (struct sockaddr*)&sender_addr, &sender_length);
    // printf("[SERVER] received %d bytes\n", rc); fflush(stdout);

    // sanity check
    if (rc <= 0) {
        printf("could not receive first SYN :/\n");
        free(temp_buffer);
        return false;
    }

    bool decap_check;
    decap_check = decapsulate_package(pshdr_addr, temp_buffer, rc);
    // printf("[SERVER] SYN decapsulated, flag = %d\n", this->tcp_hdr.get_flag()); fflush(stdout);

    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate syn packet :/\n");
        free(temp_buffer);
        return false;
    }
    // sanity check for syn
    if (!(this->tcp_hdr.get_flag() & TCP_SYN)) {
        printf("could not receive syn :/\n");
        free(temp_buffer);
        return false;
    }

    // generate new sequence number for syn-ack packet
    uint32_t seq_number = generate_random_sequence_number();
    // make new header for packet
    tcp_header syn_ack_header = tcp_header(src_port, dest_port);
    syn_ack_header.set_flag(TCP_SYN | TCP_ACK);
    syn_ack_header.set_ack_number(this->tcp_hdr.get_sequence() + 1);
    syn_ack_header.set_sequence(seq_number);

    // make new packet with no payload
    tcp_packet syn_ack_packet = tcp_packet(*pshdr_addr, syn_ack_header, nullptr, 0);

    // encapsulate package to be sent
    uint16_t package_length = 0;
    uint8_t *send_buffer = syn_ack_packet.encapsulate_package(package_length);

    // send syn-ack packet
    // printf("[SERVER] sending SYN-ACK...\n"); fflush(stdout);
    sendto(socketfd, send_buffer, package_length, 0, (struct sockaddr*)&sender_addr, sender_length);
    // printf("[SERVER] SYN-ACK sent\n"); fflush(stdout);
    free(send_buffer);

    // receive last packet
    memset(temp_buffer, 0, PAYLOAD_LENGTH + sizeof(tcp_header));

    // printf("[SERVER] waiting for ACK...\n"); fflush(stdout);
    rc = recvfrom(socketfd, temp_buffer, PAYLOAD_LENGTH + sizeof(tcp_header), 0, (struct sockaddr*)&sender_addr, &sender_length);
    // printf("[SERVER] received ACK %d bytes\n", rc); fflush(stdout);
    // sanity check
    if (rc <= 0) {
        printf("could not receive ACK :/\n");
        free(temp_buffer);
        return false;
    }

    decap_check = decapsulate_package(pshdr_addr, temp_buffer, rc);
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate syn packet :/\n");
        free(temp_buffer);
        return false;
    }
    // sanity check for ack
    if (!(this->tcp_hdr.get_flag() & TCP_ACK)) {
        printf("could not receive syn :/\n");
        free(temp_buffer);
        return false;
    }

    printf("receiver connection was established ^^\n");
    free(temp_buffer);

    return true;
}

// establish_connetion from client/sender's perspective
// -> send SYN (seq#A)
// -> receive SYN (seq#A + 1)
// -> receive ACK (seq#B + 1)
// -> send ACK (seq#B + 1)
bool tcp_packet::establish_connection_sender(int socketfd, tcp_pseudoheader *pshdr_addr, uint16_t dest_port, uint16_t src_port, struct sockaddr_in *receiver_addr) {
    // send first syn to receiver
    // generate new sequence number for syn packet
    uint32_t seq_number = generate_random_sequence_number();
    // make new header for packet
    tcp_header first_syn_header = tcp_header(src_port, dest_port);
    first_syn_header.set_flag(TCP_SYN);
    first_syn_header.set_sequence(seq_number);

    // make new packet with no payload
    tcp_packet syn_packet = tcp_packet(*pshdr_addr, first_syn_header, nullptr, 0);

    // encapsulate package to be sent
    uint16_t package_length = 0;
    uint8_t *send_buffer = syn_packet.encapsulate_package(package_length);

    // send first syn packet
    // printf("[CLIENT] sending SYN...\n"); fflush(stdout);
    sendto(socketfd, send_buffer, package_length, 0, (struct sockaddr*)receiver_addr, sizeof(* receiver_addr));
    // printf("[CLIENT] SYN sent, waiting for SYN-ACK...\n"); fflush(stdout);
    free(send_buffer);

    // new buffer to receive syn-ack packet
    uint8_t *temp_buffer = static_cast<uint8_t *>(calloc(PAYLOAD_LENGTH + sizeof(tcp_header), sizeof(uint8_t)));

    // hopefully receiving syn-ack
    socklen_t receiver_length = sizeof(*receiver_addr);
    int rc = recvfrom(socketfd, temp_buffer, PAYLOAD_LENGTH + sizeof(tcp_header), 0, (struct sockaddr*)receiver_addr, &receiver_length);
    // printf("[CLIENT] received %d bytes\n", rc); fflush(stdout);
    // sanity check
    if (rc <= 0) {
        printf("could not receive first SYN-ACK :/\n");
        free(temp_buffer);
        return false;
    }

    bool decap_check;
    decap_check = decapsulate_package(pshdr_addr, temp_buffer, rc);
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate syn-ack packet :/\n");
        free(temp_buffer);
        return false;
    }

    // sanity check for syn-ack
    if ((this->tcp_hdr.get_flag() & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK)) {
        printf("could not receive syn-ack :/\n");
        free(temp_buffer);
        return false;
    }

    // save sequence number to check next packet 
    uint32_t check_sequence = this->tcp_hdr.get_sequence();

    // generate new sequence number for ack packet
    seq_number = generate_random_sequence_number();
    // make new header for packet
    tcp_header ack_header = tcp_header(src_port, dest_port);
    ack_header.set_flag(TCP_ACK);
    ack_header.set_sequence(seq_number);
    ack_header.set_ack_number(check_sequence + 1);

    // make new packet with no payload
    tcp_packet ack_packet = tcp_packet(*pshdr_addr, ack_header, nullptr, 0);

    // encapsulate package to be sent
    package_length = 0;
    send_buffer = ack_packet.encapsulate_package(package_length);

    // send first ack packet
    sendto(socketfd, send_buffer, package_length, 0, (struct sockaddr*)receiver_addr, sizeof(* receiver_addr));
    free(send_buffer);

    printf("sender connection was established ^^\n");
    free(temp_buffer);

    return true;
}

/* ---------- 4 way handshake to finish connection --------------- */
// finish_connection from server/receiver's perspective -- passive close
// -> receive FIN(fin #m)
// -> send ACK (ack #m + 1)
// -> send FIN (fin #n)
// -> receive ACK (ack #n + 1)
// -> print finished connection receiver for debugging
bool tcp_packet::finish_connection_receiver(int socketfd, tcp_pseudoheader *pshdr_addr, uint16_t dest_port, uint16_t src_port) {
    // new buffer to receive fin packet
    uint8_t *temp_buffer = static_cast<uint8_t *>(calloc(PAYLOAD_LENGTH + sizeof(tcp_header), sizeof(uint8_t)));

    // wait to receive from sender first
    struct sockaddr_in sender_addr;
    socklen_t sender_length = sizeof(sender_addr);

    // hopefully receiving fin
    // printf("[SERVER] waiting for FIN...\n"); fflush(stdout);
    int rc = recvfrom(socketfd, temp_buffer, PAYLOAD_LENGTH + sizeof(tcp_header), 0, (struct sockaddr*)&sender_addr, &sender_length);
    // printf("[SERVER] received %d bytes\n", rc); fflush(stdout);

    // sanity check
    if (rc <= 0) {
        printf("could not get fin packet :/\n");
        free(temp_buffer);
        return false;
    }

    bool decap_check;
    decap_check = decapsulate_package(pshdr_addr, temp_buffer, rc);
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate fin packet :/\n");
        free(temp_buffer);
        return false;
    }

    // check to see if flag is fin
    if (!(this->tcp_hdr.get_flag() & TCP_FIN)) {
        printf("fin was not received :/\n");
        free(temp_buffer);
        return false;
    }

    // send ack packet with and ack_number m + 1
    // save sequence number to check next packet 
    uint32_t check_sequence = this->tcp_hdr.get_sequence();

    // make new header
    tcp_header ack_header = tcp_header(src_port, dest_port);
    ack_header.set_flag(TCP_ACK);
    ack_header.set_ack_number(check_sequence + 1);

    // prepare packet
    tcp_packet ack_packet = tcp_packet(*pshdr_addr, ack_header, nullptr, 0);

    // prepare packet to be sent 
    uint16_t package_length = 0;
    uint8_t *send_buffer = ack_packet.encapsulate_package(package_length);

    // send ack package to sender
    sendto(socketfd, send_buffer, package_length, 0, (struct sockaddr*)&sender_addr, sender_length);
    free(send_buffer);

    // send fin packet with and new seq 
    // save sequence number to check next packet 
    uint32_t new_seq_number = generate_random_sequence_number();
    // make new header
    tcp_header fin_header = tcp_header(src_port, dest_port);
    fin_header.set_flag(TCP_FIN);
    fin_header.set_sequence(new_seq_number);

    // prepare packet
    tcp_packet fin_packet = tcp_packet(*pshdr_addr, fin_header, nullptr, 0);

    // prepare packet to be sent 
    package_length = 0;
    send_buffer = fin_packet.encapsulate_package(package_length);

    // send fin package to sender
    sendto(socketfd, send_buffer, package_length, 0, (struct sockaddr*)&sender_addr, sender_length);
    free(send_buffer);

    // hopefully getting ack n + 1 to finish connection
    memset(temp_buffer, 0, PAYLOAD_LENGTH + sizeof(tcp_header));
    rc = recvfrom(socketfd, temp_buffer, PAYLOAD_LENGTH + sizeof(tcp_header), 0 , (struct sockaddr*)&sender_addr, &sender_length);

    // sanity check again
    if (rc <= 0) {
        printf("could not get ack packet :/\n");
        free(temp_buffer);
        return false;
    }

    // decapsulate package
    decap_check = decapsulate_package(pshdr_addr, temp_buffer, rc);
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate ack packet :/\n");
        free(temp_buffer);
        return false;
    }

    // check to see if flag is set to ack
    if (!(this->tcp_hdr.get_flag() & TCP_ACK)) {
        printf("fin was not received :/\n");
        free(temp_buffer);
        return false;
    }

    printf("receiver connection was finished ^^\n");
    free(temp_buffer);

    return true;
}

// finish_connection from client/sender's perspective -- active close
// -> send FIN(fin #m)
// -> receive ACK (ack #m + 1)
// -> receive FIN (fin #n)
// -> send ACK (ack #n + 1)
// -> print finished connection sebder for debugging
bool tcp_packet::finish_connection_sender(int socketfd, tcp_pseudoheader *pshdr_addr, uint16_t dest_port, uint16_t src_port, struct sockaddr_in *receiver_addr) {
    // send fin packet with m as sequence number 
    // save sequence number to check next packet 
    uint32_t new_seq_number = generate_random_sequence_number();
    // make new header
    tcp_header fin_header = tcp_header(src_port, dest_port);
    fin_header.set_flag(TCP_FIN);
    fin_header.set_sequence(new_seq_number);

    // prepare packet
    tcp_packet fin_packet = tcp_packet(*pshdr_addr, fin_header, nullptr, 0);

    // prepare packet to be sent 
    uint16_t package_length = 0;
    uint8_t *send_buffer = fin_packet.encapsulate_package(package_length);

    // send fin package to sender
    sendto(socketfd, send_buffer, package_length, 0, (struct sockaddr*)receiver_addr, sizeof(* receiver_addr));
    free(send_buffer);

    // receive ack with sequence number ack m + 1
    uint8_t *temp_buffer = static_cast<uint8_t *>(calloc(PAYLOAD_LENGTH + sizeof(tcp_header), sizeof(uint8_t)));
    
    // hopefully receiving  ack m + 1
    // printf("[CLIENT] waiting for FIN...\n"); fflush(stdout);
    socklen_t receiver_addr_len = sizeof(* receiver_addr);
    int rc = recvfrom(socketfd, temp_buffer, PAYLOAD_LENGTH + sizeof(tcp_header), 0, (struct sockaddr*)receiver_addr, &receiver_addr_len);
    // printf("[CLIENT] received %d bytes\n", rc); fflush(stdout);

    // sanity check
    if (rc <= 0) {
        printf("could not get ack m + 1 packet :/\n");
        free(temp_buffer);
        return false;
    }

    bool decap_check;
    decap_check = decapsulate_package(pshdr_addr, temp_buffer, rc);
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate ack m + 1 packet :/\n");
        free(temp_buffer);
        return false;
    }

    // check to see if flag is fin
    if (!(this->tcp_hdr.get_flag() & TCP_ACK)) {
        printf("ack m + 1 was not received :/\n");
        free(temp_buffer);
        return false;
    }

    // receive fin n
    memset(temp_buffer, 0,  PAYLOAD_LENGTH + sizeof(tcp_header));
    rc = recvfrom(socketfd, temp_buffer, PAYLOAD_LENGTH + sizeof(tcp_header), 0, (struct sockaddr*)receiver_addr, &receiver_addr_len);
    // printf("[CLIENT] received %d bytes\n", rc); fflush(stdout);

    // sanity check
    if (rc <= 0) {
        printf("could not get fin n packet :/\n");
        free(temp_buffer);
        return false;
    }

    decap_check = decapsulate_package(pshdr_addr, temp_buffer, rc);
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate fin n packet :/\n");
        free(temp_buffer);
        return false;
    }

    // check to see if flag is fin
    if (!(this->tcp_hdr.get_flag() & TCP_FIN)) {
        printf("fin n was not received :/\n");
        free(temp_buffer);
        return false;
    }

    // send final ack n + 1
    uint32_t check_sequence = this->tcp_hdr.get_sequence();

    // make new header
    tcp_header ack_header = tcp_header(src_port, dest_port);
    ack_header.set_flag(TCP_ACK);
    ack_header.set_ack_number(check_sequence + 1);

    // prepare packet
    tcp_packet ack_packet = tcp_packet(*pshdr_addr, ack_header, nullptr, 0);

    // prepare packet to be sent 
    package_length = 0;
    send_buffer = ack_packet.encapsulate_package(package_length);

    // send ack package to sender
    sendto(socketfd, send_buffer, package_length, 0, (struct sockaddr*)receiver_addr, sizeof(* receiver_addr));
    free(send_buffer);

    printf("sender connection was finished ^^\n");
    free(temp_buffer);

    return true;
}