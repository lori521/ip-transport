// TODO -- > plan de bataie
/* wrapp -> send */
/* unwrapp -> receive */
/* add inside packet ipv4 layer */
/* modify establish connection/ finish connection with ipv4 send/receive logic */

// TODO: implement send/recv logic
// modify congestion window hardcoded -> dynamic calculation
// karn's algotrithm for retransmission optimization
// modify hardcoded maximum message size 

#include "tcp_header.hpp"

// MAC hardcoded -- NEED ARP ASAP
uint8_t hardcoded_mac_2[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// send mss segmend
// send data
// -> breal into pieces <= MSS
// -> send each segment by encapsulating the packet

/* ------------------- send_segment() functions --------------------- */

// fuction to checkif last ack has been sent too long ago
void tcp_layer::check_retransmission() {
    // check if there is anything to retransmit
    if (this->snd_vars.una == this->snd_vars.nxt)
        return;

    // check if timer is on
    if (this->rto_first_unack_packet == 0)
        return;

    // check if rto time is over
    if (time_us_64() - this->rto_first_unack_packet < this->rto)
        return;

    printf("[RTO] expired! retransmitting seq=%u\n", this->snd_vars.una);

    // multipicative decrease for cwnd
    this->cwnd = max(this->cwnd / 2, (uint32_t)MSS);
    // update for slow start
    this->max_ssthresh = max((this->cwnd/2), (uint32_t)(2 * MSS));
    printf("[CWND] loss detected, cwnd=%u\n", this->cwnd);

    // if all sanity checks are passed then begin retransmission
    uint32_t nr_of_retransmit_bytes = this->snd_vars.nxt - this->snd_vars.una;
    uint current_chunk_length = 0;

    if (nr_of_retransmit_bytes < MSS)
        current_chunk_length = nr_of_retransmit_bytes;
    else
        current_chunk_length = MSS;

    uint32_t read_idx = this->tx_head & (TCP_BUFFER_SIZE - 1);

    uint8_t current_chunk[current_chunk_length];
    extract_data_from_tx_buffer(current_chunk, read_idx, current_chunk_length);

    // synchronise ack and seq inside header
    uint32_t seq_number = this->snd_vars.una;
    uint32_t ack_number = this->rcv_vars.nxt;

    // build segment header
    tcp_header segment_header = tcp_header(this->src_port, this->dest_port);
    segment_header.set_flag(TCP_ACK);
    segment_header.set_sequence(seq_number);
    segment_header.set_ack_number(ack_number);

    // build segment pseudoheader
    tcp_pseudoheader segment_pshdr = tcp_pseudoheader(this->src_ip, this->dest_ip, 20 + current_chunk_length);
    
    // build segment packet
    tcp_packet segment_packet = tcp_packet(segment_pshdr, segment_header, current_chunk, current_chunk_length);

    // encapsulate current chunk call SendIpPacket()
    uint16_t final_package_length = 0;
    uint8_t *raw_buffer = segment_packet.encapsulate_package(&segment_pshdr, final_package_length);

    // sending the data through the ip layer
    vector<uint8_t> send_payload(raw_buffer, raw_buffer + final_package_length);
    char dest_ip_str[16];
    encode_ip_address(this->dest_ip, dest_ip_str);
    ipv4_layer.SendIPPacket(send_payload, dest_ip_str, hardcoded_mac_2);

    free(raw_buffer);
    segment_packet.free_package();

    // this->rto = min(this->rto * 2, (uint32_t)60000000);
    if (this->rto * 2 < (uint32_t)60000000)
        this->rto *= 2;
    else
        this->rto = (uint32_t)60000000;
    
    this->rto_first_unack_packet = time_us_64();
}

// helper function to write data in tx_buffer
bool tcp_layer::write_data_in_tx_buffer(uint8_t* payload, uint16_t payload_length) {
    // used space in buffer
    uint32_t buffer_used_space = this->tx_tail - this->tx_head;

    // check if there is enough space in buffer
    if (TCP_BUFFER_SIZE - buffer_used_space < payload_length) {
        printf("there is not enough space inside tcp ring buffer :(\n)");
        return false;
    }

    // you can copy the data
    // same as tx_tail % TCP_BUFFER_SIZE but optimized for pico
    uint32_t write_idx = this->tx_tail & (TCP_BUFFER_SIZE - 1);

    uint32_t buffer_space_left = TCP_BUFFER_SIZE - write_idx;

    // case 1 -> there is enough space to copy all the data
    if (payload_length <= buffer_space_left) {
        memcpy(tx_buffer + write_idx, payload, payload_length);
        
    } else {
        // case 2 -> copy all a part inside the space left and the other in the beginning of the buffer
        memcpy(this->tx_buffer + write_idx, payload, buffer_space_left);
        
        memcpy(this->tx_buffer, payload + buffer_space_left, payload_length - buffer_space_left);
    }
    
    // update tail pointer
    tx_tail += payload_length; 

    printf("all the data was successfully copied inside the tcp ring buffer :))\n");
    return true;
}

// helper function to extract data from tx_buffer
void tcp_layer::extract_data_from_tx_buffer(uint8_t* current_chunk_data, uint32_t read_idx, uint32_t current_chunk_length) {

    uint32_t buffer_space_left = TCP_BUFFER_SIZE - read_idx;

    if (current_chunk_length <= buffer_space_left) {
        // no wrap around needed
        memcpy(current_chunk_data, this->tx_buffer + read_idx, current_chunk_length);
    } else {
        // wrapp around needed
        memcpy(current_chunk_data, this->tx_buffer + read_idx, buffer_space_left);
        memcpy(current_chunk_data + buffer_space_left, this->tx_buffer, current_chunk_length - buffer_space_left);
    }
}

/* ------------------- send_segment() functions --------------------- */

// send data segment -> returns nr of bytes send or 0 if the ipv4 layer is busy or does not have data to send (non blocking)
// prototype without window logic and slow start
uint32_t tcp_layer::send_segment(uint8_t* payload, uint32_t payload_length) {
    // check for retransmission firstly
    check_retransmission();

    // sanity check for connection establishment
    if (this->current_state != ESTABLISHED) {
        printf("could not send segment because th connection has not been established :/\n");
        return 0;
    }

    // if payload is not empty and data can pe written inside tx_buffer
    if (payload != nullptr && payload_length > 0) {
        bool write_check = write_data_in_tx_buffer(payload, payload_length);
        if (!write_check)
            return 0;
    }

    // segmentation part ig
    uint32_t bytes_read = 0;

    // check the number of packets in flight 
    uint32_t number_of_bytes_in_flight = this->snd_vars.nxt - this->snd_vars.una;

    // 
    uint32_t number_of_untracked_bytes = this->tx_tail - this->tx_head;

    // check if there is data left in the buffer
    while (number_of_bytes_in_flight < number_of_untracked_bytes && number_of_bytes_in_flight < this->cwnd) {
        printf("[SEND] sending chunk, bytes_in_flight=%u cwnd=%u\n", number_of_bytes_in_flight, this->cwnd);
        uint32_t data_left = number_of_untracked_bytes - number_of_bytes_in_flight;
        uint32_t current_chunk_length = 0;

        
        if (data_left < MSS)
            current_chunk_length = data_left;
        else 
            current_chunk_length = MSS;

        // find out read position
        uint32_t absolute_read_pos = this->tx_head + number_of_bytes_in_flight;
        uint32_t read_idx = absolute_read_pos & (TCP_BUFFER_SIZE - 1);

        uint8_t current_chunk_data[MSS];
        extract_data_from_tx_buffer(current_chunk_data, read_idx, current_chunk_length);

        // synchronise ack and seq inside header
        uint32_t seq_number = this->snd_vars.nxt;
        uint32_t ack_number = this->rcv_vars.nxt;

        // build segment header
        tcp_header segment_header = tcp_header(this->src_port, this->dest_port);
        segment_header.set_flag(TCP_ACK);
        segment_header.set_sequence(seq_number);
        segment_header.set_ack_number(ack_number);

        // build segment pseudoheader
        tcp_pseudoheader segment_pshdr = tcp_pseudoheader(this->src_ip, this->dest_ip, 20 + current_chunk_length);
        
        // build segment packet
        tcp_packet segment_packet = tcp_packet(segment_pshdr, segment_header, current_chunk_data, current_chunk_length);

        // encapsulate current chunk call SendIpPacket()
        uint16_t final_package_length = 0;
        uint8_t *raw_buffer = segment_packet.encapsulate_package(&segment_pshdr, final_package_length);

        // sending the data through the ip layer
        vector<uint8_t> send_payload(raw_buffer, raw_buffer + final_package_length);
        char dest_ip_str[16];
        encode_ip_address(this->dest_ip, dest_ip_str);
        ipv4_layer.SendIPPacket(send_payload, dest_ip_str, hardcoded_mac_2);

        if (number_of_bytes_in_flight == 0) {
            printf("[TIMER] started\n");
            this->rto_first_unack_packet = time_us_64();
        }

        free(raw_buffer);
        segment_packet.free_package();

        // sync send vars
        this->snd_vars.nxt += current_chunk_length;
        number_of_bytes_in_flight += current_chunk_length;
        bytes_read += current_chunk_length;

        break;
    }
    return bytes_read;
}

// helper function to write data in rx_buffer
bool tcp_layer::write_data_in_rx_buffer(uint8_t* payload, uint16_t payload_length) {
    // used space in buffer
    uint32_t buffer_used_space = this->rx_tail - this->rx_head;

    // check if there is enough space in buffer
    if (TCP_BUFFER_SIZE - buffer_used_space < payload_length) {
        printf("there is not enough space inside tcp ring buffer :(\n)");
        return false;
    }

    // you can copy the data
    // same as tx_tail % TCP_BUFFER_SIZE but optimized for pico
    uint32_t write_idx = this->rx_tail & (TCP_BUFFER_SIZE - 1);

    uint32_t buffer_space_left = TCP_BUFFER_SIZE - write_idx;

    // case 1 -> there is enough space to copy all the data
    if (payload_length <= buffer_space_left) {
        memcpy(rx_buffer + write_idx, payload, payload_length);
        
    } else {
        // case 2 -> copy all a part inside the space left and the other in the beginning of the buffer
        memcpy(this->rx_buffer + write_idx, payload, buffer_space_left);
        
        memcpy(this->rx_buffer, payload + buffer_space_left, payload_length - buffer_space_left);
    }
    
    // update tail pointer
    rx_tail += payload_length; 

    printf("all the data was successfully copied inside the tcp ring buffer :))\n");
    return true;
}

// helper function to extract data from rx_buffer
void tcp_layer::extract_data_from_rx_buffer(uint8_t* current_chunk_data, uint32_t read_idx, uint32_t current_chunk_length) {

    uint32_t buffer_space_left = TCP_BUFFER_SIZE - read_idx;

    if (current_chunk_length <= buffer_space_left) {
        // no wrap around needed
        memcpy(current_chunk_data, this->rx_buffer + read_idx, current_chunk_length);
    } else {
        // wrapp around needed
        memcpy(current_chunk_data, this->rx_buffer + read_idx, buffer_space_left);
        memcpy(current_chunk_data + buffer_space_left, this->rx_buffer, current_chunk_length - buffer_space_left);
    }
}

uint32_t tcp_layer::receive_segment() {
    if (this->current_state != ESTABLISHED) {
        printf("could not receive segment because th connection has not been established :/\n");
        return 0;
    }

    vector<uint8_t> received_payload;
    ipv4_packet_header received_ip_header;
    // receive an ip packet to be read
    bool check = ipv4_layer.ReadIPPacket(received_payload, received_ip_header);

    // sanity check to find out if the received packet actually exists :')
    if (!check || received_payload.empty()) {
        // printf("could not receive any ip packet\n");
        return 0;
    }

    // get ip addresses
    uint32_t src_ip = received_ip_header.source_ip_address;
    uint32_t dest_ip = received_ip_header.destination_ip_address;

    // get pseudoheader to decap ip packet
    // tcp_pseudoheader(uint32_t source_ip, uint32_t destination_ip, uint16_t tcp_length);
    tcp_pseudoheader decap_ip_pshdr = tcp_pseudoheader(src_ip, dest_ip, received_payload.size());
    
    // receive packet
    tcp_packet received_packet;
    check = received_packet.decapsulate_package(&decap_ip_pshdr, received_payload.data(), received_payload.size());

    // sanity check if everything was good including checksum verification
    if (!check) {
        printf("could not decapsulate ip packet :/\n");
        received_packet.free_package();
        return 0;
    }

    /* PACKET DROP SIMULATIOB */
    if (this->simulate_drop) {
        this->drop_counter++;
        if (this->drop_counter == 2) {
            printf("[DROP] dropping packet with seq=%u\n", received_packet.tcp_hdr.get_sequence());
            received_packet.free_package();
            this->simulate_drop = false;
            this->drop_counter = 0;
            return 0;
        }
    }

    // sequence number verification
    if (this->rcv_vars.nxt != received_packet.tcp_hdr.get_sequence()) {
        received_packet.free_package();
        return 0;
    }

    if (received_packet.tcp_hdr.get_flag() & TCP_ACK) {
        // get the number of bytes we just received verification for (happy happy happy)
        uint32_t number_of_ack_bytes = received_packet.tcp_hdr.get_ack_number() - this->snd_vars.una;

        if (number_of_ack_bytes > 0 && number_of_ack_bytes <= this->snd_vars.nxt - this->snd_vars.una) {
            this->snd_vars.una = received_packet.tcp_hdr.get_ack_number();
            this->tx_head += number_of_ack_bytes;

            // additive increase for cwnd
            if (this->cwnd <= this->max_ssthresh) {
                printf("[SLOW START] cwnd value is: %d\n", this->cwnd);
                this->cwnd += MSS;
            } else {
                this->cwnd += (int)(this->cwnd / (0.5 * this->max_ssthresh));
            }
            printf("[CWND] ACK received, cwnd=%u\n", this->cwnd);

            // implement retransmission logic
            if (this->snd_vars.una < this->snd_vars.nxt)
                this->rto_first_unack_packet = time_us_64();
            else
                this->rto_first_unack_packet = 0;
            
            this->rto = 1000000;
        }
    }

    // copy data inside rx_buffer
    uint32_t received_bytes = 0;
    if (received_packet.payload_length > 0) {
        write_data_in_rx_buffer(received_packet.payload, received_packet.payload_length);
        this->rcv_vars.nxt += received_packet.payload_length;
        received_bytes = received_packet.payload_length;
    }

    if (received_bytes > 0) {
        // send ack for this packet

        // build pshdr
        tcp_pseudoheader ack_pshdr = tcp_pseudoheader(this->src_ip, this->dest_ip, 20);

        // build header
        tcp_header ack_header = tcp_header(this->src_port, this->dest_port);
        ack_header.set_flag(TCP_ACK);

        uint32_t sequence_number = this->snd_vars.nxt;
        uint32_t ack_number = this->rcv_vars.nxt;

        // sync ack and seq
        ack_header.set_sequence(sequence_number);
        ack_header.set_ack_number(ack_number);

        // build package
        tcp_packet ack_packet = tcp_packet(ack_pshdr, ack_header, nullptr, 0);

        // encapsulate packet
        uint16_t package_length = 0;
        uint8_t *raw_buffer = ack_packet.encapsulate_package(&ack_pshdr, package_length);

        // sending the data through the ip layer
        vector<uint8_t> send_payload(raw_buffer, raw_buffer + package_length);
        char dest_ip_str[16];
        encode_ip_address(this->dest_ip, dest_ip_str);
        ipv4_layer.SendIPPacket(send_payload, dest_ip_str, hardcoded_mac_2);

        free(raw_buffer);
        ack_packet.free_package();
    }

    received_packet.free_package();
    return received_bytes;
}

uint32_t tcp_layer::read_data(uint8_t* destination, uint32_t length_to_read) {
    uint32_t available_data = this->rx_tail - this->rx_head;
    
    uint32_t actual_read_len = (length_to_read < available_data) ? length_to_read : available_data;

    if (actual_read_len == 0) return 0;

    uint32_t read_idx = this->rx_head & (TCP_BUFFER_SIZE - 1);

    this->extract_data_from_rx_buffer(destination, read_idx, actual_read_len);

    this->rx_head += actual_read_len;

    return actual_read_len;
}