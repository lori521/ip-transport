// TODO -- >> plan de bataie
/* wrapp -> send */
/* unwrapp -> receive */
/* add inside packet ipv4 layer */
/* modify establish connection/ finish connection with ipv4 send/receive logic */

// TODO: implement send/recv logic
// modify congestion window hardcoded -> dynamic calculation
// karn's algotrithm for retransmission optimization
// modify hardcoded maximum message size 

#include "tcp_header.hpp"

// send mss segmend
// send data
// -> breal into pieces <= MSS
// -> send each segment by encapsulating the packet
bool tcp_layer::write_data_in_buffer(uint8_t* payload, uint16_t payload_length) {
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