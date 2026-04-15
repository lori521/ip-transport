#include "tcp_header.hpp"

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

    // check sequence
    if (this->tcp_hdr.get_ack_number() != seq_number + 1) {
        printf("ACK number is incorrect :/ (receiver)\n");
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

    // check sequence
    if (this->tcp_hdr.get_ack_number() != seq_number + 1) {
        printf("SYN-ACK number is incorrect :/ (sender)\n");
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
        printf("ack n + 1 was not received :/\n");
        free(temp_buffer);
        return false;
    }

    // sequence number check
    if (this->tcp_hdr.get_ack_number() != new_seq_number + 1) {
        printf("ACK number is incorrect :/ (receiver)\n");
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

    if (this->tcp_hdr.get_ack_number() != new_seq_number + 1) {
        printf("ack m + 1 could not match\n");
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