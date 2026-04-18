#include "tcp_header.hpp"

// MAC de broadcast temporar pentru a trece de compilare si testare
uint8_t hardcoded_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ---------- 3 way handshake to open connection --------------- */
// establish_connetion from server/receiver's perspective
// -> receive SYN(syn#A)
// -> send ACK-SYN (ack#B, syn#A + 1) 
// -> receive ACK (ack#B + 1)
// -> print connection established server for debugging
bool tcp_layer::establish_connection_receiver(char* dest_ip, uint16_t dest_port, uint16_t src_port) {
    // receive ip packet vector
    vector<uint8_t> received_payload;
    char received_sender_ip[16];
    bool check;

    switch (this->get_state())
    {
    case CLOSED: {
        printf("[SERVER] waiting for SYN...\n"); fflush(stdout);
        this->set_state(LISTEN);
        return false;
    }
    case LISTEN: {
        // receive ip packet
        check = ipv4_layer.ReadIPPacket(received_payload, received_sender_ip);

        // check if the packet was received
        if (!check) {
            // DEBUG
            // printf("[SERVER] could not receive syn ip packet\n"); fflush(stdout);
            return false;
        }

        // check if the packet was sent from a different ip address
        if (inet_addr(received_sender_ip) == ipv4_layer.GetSourceAddress()) {
            // DEBUG
            // printf("[SERVER] could not receive syn ip packet from the same ip address\n"); fflush(stdout);
            return false;
        }

        // get ip addresses
        uint32_t receiver_ip_addr = ipv4_layer.GetSourceAddress();
        uint32_t sender_ip_addr = inet_addr(received_sender_ip);

        // get pseudoheader
        tcp_pseudoheader syn_pshdr = tcp_pseudoheader(sender_ip_addr, receiver_ip_addr, received_payload.size());

        tcp_packet received_packet;
        check = received_packet.decapsulate_package(&syn_pshdr, received_payload.data(), received_payload.size());

        // sanity check for decapsulation
        if (!check) {
            // DEBUG
            // printf("could not decapsulate syn packet :/\n");
            return false;
        }

        // sanity check for syn
        if (!(received_packet.tcp_hdr.get_flag() & TCP_SYN)) {
            // DEBUG
            // printf("could not receive syn :/\n");
            return false;
        }

        // all good then syn was received
        this->set_state(SYN_RECEIVED);

        // prepare syn-ack packet to be sent
        // generate new sequence number for syn-ack packet
        this->saved_seq_num = generate_random_sequence_number();
        // make new header for packet
        tcp_header syn_ack_header = tcp_header(src_port, dest_port);
        syn_ack_header.set_flag(TCP_SYN | TCP_ACK);
        syn_ack_header.set_ack_number(received_packet.tcp_hdr.get_sequence() + 1);
        syn_ack_header.set_sequence(this->saved_seq_num);

        // generate syn-ack pseudoheader
        tcp_pseudoheader syn_ack_pshdr(receiver_ip_addr, sender_ip_addr, 20);

        // make new packet with no payload
        tcp_packet syn_ack_packet = tcp_packet(syn_ack_pshdr, syn_ack_header, nullptr, 0);

        // encapsulate package to be sent
        uint16_t package_length = 0;
        uint8_t *send_buffer = syn_ack_packet.encapsulate_package(&syn_ack_pshdr ,package_length);

        // convert buffer and free memory
        vector<uint8_t> send_payload(send_buffer, send_buffer + package_length);
        free(send_buffer);
        // send syn-ack packet
        printf("[SERVER] sending SYN-ACK...\n"); fflush(stdout);
        ipv4_layer.SendIPPacket(send_payload, received_sender_ip, hardcoded_mac);
        printf("[SERVER] SYN-ACK sent, waiting for ACK...\n"); fflush(stdout);
        
        // clear buffer
        received_payload.clear();
        return false;
    }

    case SYN_RECEIVED: {
        // receive ip packet
        check = ipv4_layer.ReadIPPacket(received_payload, received_sender_ip);

        // check if the packet was received
        if (!check) {
            // DEBUG
            // printf("[SERVER] could not receive ack ip packet\n"); fflush(stdout);
            return false;
        }

        // check if the packet was sent from a different ip address
        if (inet_addr(received_sender_ip) == ipv4_layer.GetSourceAddress()) {
            // DEBUG
            // printf("[SERVER] could not receive ack ip packet from the same ip address\n"); fflush(stdout);
            return false;
        }

        // get ip addresses
        uint32_t receiver_ip_addr = ipv4_layer.GetSourceAddress();
        uint32_t sender_ip_addr = inet_addr(received_sender_ip);

        // make pseudoheader
        tcp_pseudoheader ack_pshdr = tcp_pseudoheader(sender_ip_addr, receiver_ip_addr, received_payload.size());
        
        // decapsulate package
        tcp_packet received_packet;
        check = received_packet.decapsulate_package(&ack_pshdr, received_payload.data(), received_payload.size());
        // sanity check for decapsulation
        if (!check) {
            // DEBUG
            // printf("could not decapsulate syn packet :/\n");
            return false;
        }
        // sanity check for ack
        if (!(received_packet.tcp_hdr.get_flag() & TCP_ACK)) {
            // DEBUG
            // printf("could not receive syn :/\n");
            return false;
        }

        // check sequence
        if (received_packet.tcp_hdr.get_ack_number() != this->saved_seq_num + 1) {
            // DEBUG
            // printf("ACK number is incorrect :/ (receiver)\n");
            return false;
        }

        printf("receiver connection was established ^^\n");

        // update state
        this->set_state(ESTABLISHED);
    
        return true;
    }

    case ESTABLISHED: {
        return true;
    }

    default:
        return false;
    }
}

// establish_connetion from client/sender's perspective
// -> send SYN (seq#A)
// -> receive SYN (seq#A + 1)
// -> receive ACK (seq#B + 1)
// -> send ACK (seq#B + 1)
bool tcp_layer::establish_connection_sender(char* dest_ip, uint16_t dest_port, uint16_t src_port) {
    // receive ip packet vector
    vector<uint8_t> received_payload;
    char received_sender_ip[16];
    bool check;

    // get ip addresses
    uint32_t sender_ip_addr = ipv4_layer.GetSourceAddress();
    uint32_t receiver_ip_addr = inet_addr(dest_ip);

    switch (this->current_state)
    {
    case CLOSED: {
        // generate new sequence number for syn packet
        this->saved_seq_num = generate_random_sequence_number();
        // make new pseudoheader
        tcp_pseudoheader syn_pshdr = tcp_pseudoheader(sender_ip_addr, receiver_ip_addr, 20);
        // make new header for packet
        tcp_header first_syn_header = tcp_header(src_port, dest_port);
        first_syn_header.set_flag(TCP_SYN);
        first_syn_header.set_sequence(this->saved_seq_num);

        // make new packet with no payload
        tcp_packet syn_packet = tcp_packet(syn_pshdr, first_syn_header, nullptr, 0);

        // encapsulate package to be sent
        uint16_t package_length = 0;
        uint8_t *send_buffer = syn_packet.encapsulate_package(&syn_pshdr, package_length);

        // send first syn packet
        printf("[CLIENT] sending SYN...\n"); fflush(stdout);
        // convert buffer
        vector<uint8_t> send_payload(send_buffer, send_buffer + package_length);
        free(send_buffer);
        ipv4_layer.SendIPPacket(send_payload, dest_ip, hardcoded_mac);
        printf("[CLIENT] SYN sent, waiting for SYN-ACK...\n"); fflush(stdout);
        
        syn_packet.free_package();
        
        // update state
        this->set_state(SYN_SENT);
        return false;
    }

    case SYN_SENT: {
        // receive ip packet
        check = ipv4_layer.ReadIPPacket(received_payload, received_sender_ip);

        // check if packet could be received
        if (!check)  {
            return false;
        } 

        // check if the send ip addr is different from the recv ip addr
        if (inet_addr(received_sender_ip) == sender_ip_addr) {
            return false;
        }

        // creat pseudoheader
        tcp_pseudoheader syn_ack_pshdr = tcp_pseudoheader(inet_addr(received_sender_ip), sender_ip_addr, received_payload.size());

        tcp_packet received_packet;
        check = received_packet.decapsulate_package(&syn_ack_pshdr, received_payload.data(), received_payload.size());
        // sanity check for decapsulation
        if (!check) {
            printf("could not decapsulate syn-ack packet :/\n");
            received_packet.free_package();
            return false;
        }

        // sanity check for syn-ack
        if ((received_packet.tcp_hdr.get_flag() & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK)) {
            printf("could not receive syn-ack :/\n");
            received_packet.free_package();
            return false;
        }

        // check sequence
        if (received_packet.tcp_hdr.get_ack_number() != this->saved_seq_num + 1) {
            printf("SYN-ACK number is incorrect :/ (sender)\n");
            received_packet.free_package();
            return false;
        }

        // prepare to send ack packet
        // save sequence number to check next packet 
        uint32_t check_sequence = received_packet.tcp_hdr.get_sequence();

        received_packet.free_package();

        // make new header for packet
        tcp_header ack_header = tcp_header(src_port, dest_port);
        ack_header.set_flag(TCP_ACK);
        ack_header.set_sequence(this->saved_seq_num + 1);
        ack_header.set_ack_number(check_sequence + 1);

        // create pseudoheader
        tcp_pseudoheader ack_pshdr = tcp_pseudoheader(sender_ip_addr, inet_addr(received_sender_ip), 20);

        // make new packet with no payload
        tcp_packet ack_packet = tcp_packet(ack_pshdr, ack_header, nullptr, 0);

        // encapsulate package to be sent
        uint16_t package_length = 0;
        uint8_t* send_buffer = ack_packet.encapsulate_package(&ack_pshdr, package_length);

        // send first ack packet
        vector<uint8_t> ack_payload(send_buffer, send_buffer + package_length);
        free(send_buffer);

        ipv4_layer.SendIPPacket(ack_payload, received_sender_ip, hardcoded_mac);
        ack_packet.free_package();

        printf("sender connection was established ^^\n");

        // update state
        this->set_state(ESTABLISHED);
        return true;
    }

    case ESTABLISHED: {
        return true;
    }

    default:
        return false;
    }
}


/* ---------- 4 way handshake to finish connection --------------- */
// finish_connection from server/receiver's perspective -- passive close
// -> receive FIN(fin #m)
// -> send ACK (ack #m + 1)
// -> send FIN (fin #n)
// -> receive ACK (ack #n + 1)
// -> print finished connection receiver for debugging
bool tcp_layer::finish_connection_receiver(char *dest_ip, uint16_t dest_port, uint16_t src_port) {
    // new buffer to receive fin packet
    // receive ip packet vector
    vector<uint8_t> received_payload;
    char received_sender_ip[16];

    // update state 
    this->current_state = LISTEN;


    // hopefully receiving fin
    printf("[SERVER] waiting for FIN...\n"); fflush(stdout);
    bool check;
    bool valid_packet = false;
    while (!valid_packet) {
        check = ipv4_layer.ReadIPPacket(received_payload, received_sender_ip);
        if (!check)  {
            sleep_ms(2);
            continue;
        } 
    
        if (inet_addr(received_sender_ip) != ipv4_layer.GetSourceAddress()) {
            valid_packet = true;
        } else {
            printf("[CLIENT] Ignoring loopback, retrying...\n");
            received_payload.clear();
        }
    }
    // printf("[SERVER] received %d bytes\n", rc); fflush(stdout);

    // sanity check
    if (!check) {
        printf("could not get fin packet :/\n");
        return false;
    }

    uint32_t receiver_ip_addr = ipv4_layer.GetSourceAddress();
    uint32_t sender_ip_addr = inet_addr(received_sender_ip);

    // create pseudoheader
    tcp_pseudoheader fin_pshdr = tcp_pseudoheader(sender_ip_addr, receiver_ip_addr, received_payload.size());

    bool decap_check;
    tcp_packet received_packet;
    decap_check = received_packet.decapsulate_package(&fin_pshdr, received_payload.data(), received_payload.size());

    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate fin packet :/\n");
        return false;
    }

    // check to see if flag is fin
    if (!(received_packet.tcp_hdr.get_flag() & TCP_FIN)) {
        printf("fin was not received :/\n");
        return false;
    }

    // send ack packet with and ack_number m + 1
    // save sequence number to check next packet 
    uint32_t check_sequence = received_packet.tcp_hdr.get_sequence();
    received_payload.clear();
    received_packet.free_package();

    // update state
    this->current_state = CLOSE_WAIT;

    // make new header
    tcp_header ack_header = tcp_header(src_port, dest_port);
    ack_header.set_flag(TCP_ACK);
    ack_header.set_ack_number(check_sequence + 1);

    // create pseudoheader
    tcp_pseudoheader ack_pshdr = tcp_pseudoheader(receiver_ip_addr, sender_ip_addr, 20);
    // prepare packet
    tcp_packet ack_packet = tcp_packet(ack_pshdr, ack_header, nullptr, 0);

    // prepare packet to be sent 
    uint16_t package_length = 0;
    uint8_t *send_buffer = ack_packet.encapsulate_package(&ack_pshdr, package_length);
    vector<uint8_t> ack_payload(send_buffer, send_buffer + package_length);
    free(send_buffer);

    // send ack package to sender
    ipv4_layer.SendIPPacket(ack_payload, received_sender_ip, hardcoded_mac);
    ack_packet.free_package();

    // update state
    this->current_state = LAST_ACK;

    // send fin packet with and new seq 
    // save sequence number to check next packet 
    uint32_t new_seq_number = generate_random_sequence_number();
    // make new header
    tcp_header fin_header = tcp_header(src_port, dest_port);
    fin_header.set_flag(TCP_FIN);
    fin_header.set_sequence(new_seq_number);

    // create pseudoheader
    tcp_pseudoheader fin_send_pshdr = tcp_pseudoheader(receiver_ip_addr, sender_ip_addr, 20);

    // prepare packet
    tcp_packet fin_packet = tcp_packet(fin_send_pshdr, fin_header, nullptr, 0);

    // prepare packet to be sent 
    package_length = 0;
    send_buffer = fin_packet.encapsulate_package(&fin_send_pshdr, package_length);
    vector<uint8_t> fin_payload(send_buffer, send_buffer + package_length);
    free(send_buffer);

    // send fin package to sender
    ipv4_layer.SendIPPacket(fin_payload, received_sender_ip, hardcoded_mac);
    fin_packet.free_package();

    // hopefully getting ack n + 1 to finish connection
    received_payload.clear();

    valid_packet = false;
    while (!valid_packet) {
        check = ipv4_layer.ReadIPPacket(received_payload, received_sender_ip);
        if (!check)  {
            sleep_ms(2);
            continue;
        } 
        
        // Verifică dacă nu e loopback
        if (inet_addr(received_sender_ip) != ipv4_layer.GetSourceAddress()) {
            valid_packet = true;
        } else {
            printf("[CLIENT] Ignoring loopback, retrying...\n");
            received_payload.clear();
        }
    }

    // create pseudoheader
    tcp_pseudoheader final_ack = tcp_pseudoheader(sender_ip_addr, receiver_ip_addr, received_payload.size());
    // decapsulate package
    decap_check = received_packet.decapsulate_package(&final_ack, received_payload.data(), received_payload.size());
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate ack packet :/\n");
        return false;
    }

    // check to see if flag is set to ack
    if (!(received_packet.tcp_hdr.get_flag() & TCP_ACK)) {
        printf("ack n + 1 was not received :/\n");
        return false;
    }
    // update state
    this->current_state = LAST_ACK;

    // sequence number check
    if (received_packet.tcp_hdr.get_ack_number() != new_seq_number + 1) {
        printf("ACK number is incorrect :/ (receiver)\n");
        return false;
    }

    printf("receiver connection was finished ^^\n");

    received_payload.clear();
    received_packet.free_package();

    // update state
    this->current_state = CLOSED;

    return true;
}

// finish_connection from client/sender's perspective -- active close
// -> send FIN(fin #m)
// -> receive ACK (ack #m + 1)
// -> receive FIN (fin #n)
// -> send ACK (ack #n + 1)
// -> print finished connection sebder for debugging
bool tcp_layer::finish_connection_sender(char* dest_ip, uint16_t dest_port, uint16_t src_port) {
    uint32_t sender_ip_addr = ipv4_layer.GetSourceAddress();
    uint32_t receiver_ip_addr = inet_addr(dest_ip);
    
    // send fin packet with m as sequence number 
    // save sequence number to check next packet 
    uint32_t new_seq_number = generate_random_sequence_number();
    // make new header
    tcp_header fin_header = tcp_header(src_port, dest_port);
    fin_header.set_flag(TCP_FIN);
    fin_header.set_sequence(new_seq_number);

    // create pseudoheader
    tcp_pseudoheader fin_pshdr = tcp_pseudoheader(sender_ip_addr, receiver_ip_addr, 20);

    // prepare packet
    tcp_packet fin_packet = tcp_packet(fin_pshdr, fin_header, nullptr, 0);

    // prepare packet to be sent 
    uint16_t package_length = 0;
    uint8_t *send_buffer = fin_packet.encapsulate_package(&fin_pshdr, package_length);
    vector<uint8_t> send_payload(send_buffer, send_buffer + package_length);
    free(send_buffer);

    // send fin package to sender
    ipv4_layer.SendIPPacket(send_payload, dest_ip, hardcoded_mac);
    fin_packet.free_package();

    // update state
    this->current_state = FIN_WAIT_1;

    // receive ack with sequence number ack m + 1
    vector<uint8_t> received_payload;
    char received_sender_ip[16];
    
    // hopefully receiving  ack m + 1
    printf("[CLIENT] waiting for FIN...\n"); fflush(stdout);

    bool check;
    bool valid_packet = false;
    while (!valid_packet) {
        check = ipv4_layer.ReadIPPacket(received_payload, received_sender_ip);
        if (!check)  {
            sleep_ms(2);
            continue;
        } 
    
        if (inet_addr(received_sender_ip) != ipv4_layer.GetSourceAddress()) {
            valid_packet = true;
        } else {
            printf("[CLIENT] Ignoring loopback, retrying...\n");
            received_payload.clear();
        }
    }
    // printf("[CLIENT] received %d bytes\n", rc); fflush(stdout);

    // sanity check
    if (!check) {
        printf("could not get ack m + 1 packet :/\n");
        return false;
    }

    // create pseudoheader
    tcp_pseudoheader ack_recv_pshdr = tcp_pseudoheader(receiver_ip_addr, sender_ip_addr, received_payload.size());

    bool decap_check;
    tcp_packet received_packet;
    decap_check = received_packet.decapsulate_package(&ack_recv_pshdr, received_payload.data(), received_payload.size());
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate ack m + 1 packet :/\n");
        return false;
    }

    // check to see if flag is fin
    if (!(received_packet.tcp_hdr.get_flag() & TCP_ACK)) {
        printf("ack m + 1 was not received :/\n");
        return false;
    }

    if (received_packet.tcp_hdr.get_ack_number() != new_seq_number + 1) {
        printf("ack m + 1 could not match\n");
        return false;
    }

    received_payload.clear();
    received_packet.free_package();
    
    // update state
    this->current_state = FIN_WAIT_2;

    // receive fin n
    valid_packet = false;
    while (!valid_packet) {
        check = ipv4_layer.ReadIPPacket(received_payload, received_sender_ip);
        if (!check) {
            sleep_ms(2);
            continue;
        } 
    
        if (inet_addr(received_sender_ip) != ipv4_layer.GetSourceAddress()) {
            valid_packet = true;
        } else {
            printf("[CLIENT] Ignoring loopback, retrying...\n");
            received_payload.clear();
        }
    }
    // printf("[CLIENT] received %d bytes\n", rc); fflush(stdout);

    // sanity check
    if (!check) {
        printf("could not get fin n packet :/\n");
        return false;
    }

    // create pseudoheader
    tcp_pseudoheader fin_recv_pshdr = tcp_pseudoheader(receiver_ip_addr, sender_ip_addr, received_payload.size());

    decap_check = received_packet.decapsulate_package(&fin_recv_pshdr, received_payload.data(), received_payload.size());
    // sanity check for decapsulation
    if (!decap_check) {
        printf("could not decapsulate fin n packet :/\n");
        return false;
    }

    // check to see if flag is fin
    if (!(received_packet.tcp_hdr.get_flag() & TCP_FIN)) {
        printf("fin n was not received :/\n");
        return false;
    }

    // send final ack n + 1
    uint32_t check_sequence = received_packet.tcp_hdr.get_sequence();
    received_payload.clear();
    received_packet.free_package();

    // make new header
    tcp_header ack_header = tcp_header(src_port, dest_port);
    ack_header.set_flag(TCP_ACK);
    ack_header.set_ack_number(check_sequence + 1);

    // create pseudoheader
    tcp_pseudoheader ack_pshdr = tcp_pseudoheader(sender_ip_addr, receiver_ip_addr, 20);

    // prepare packet
    tcp_packet ack_packet = tcp_packet(ack_pshdr, ack_header, nullptr, 0);

    // prepare packet to be sent 
    package_length = 0;
    send_buffer = ack_packet.encapsulate_package(&ack_pshdr, package_length);
    vector<uint8_t> final_ack_payload(send_buffer, send_buffer + package_length);
    free(send_buffer);

    // send ack package to sender
    ipv4_layer.SendIPPacket(final_ack_payload, dest_ip, hardcoded_mac);
    ack_packet.free_package();

    printf("sender connection was finished ^^\n");

    // update state
    this->current_state = TIME_WAIT;

    return true;
}