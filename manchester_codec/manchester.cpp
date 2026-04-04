#include "manchester.hpp"
#include <time.h>
void Manchester::init(uint8_t tx_pin, uint8_t rx_pin, uint32_t baud_rate, uint32_t clock_period_us)
{
    this->tx_pin = tx_pin;
    this->rx_pin = rx_pin;
    this->baud_rate = baud_rate;
    this->clock_period_us = clock_period_us;

    // Set up the TX pin
    gpio_init(this->tx_pin);
    gpio_set_dir(this->tx_pin, GPIO_OUT);

    // Set up the RX pin
    gpio_init(this->rx_pin);
    gpio_set_dir(this->rx_pin, GPIO_IN);
}

int Manchester::receive_manchester_bit() {
    busy_wait_us(this->clock_period_us >> 2);
    int first_half = gpio_get(this->rx_pin);
    
    busy_wait_us(this->clock_period_us >> 1);
    int second_half = gpio_get(this->rx_pin);
    
    busy_wait_us(this->clock_period_us >> 2); 

    if (first_half == 0 && second_half == 1) {
            return 1;
    } else if (first_half == 1 && second_half == 0) {
        return 0;
    }

    return -1;
}

int Manchester::receive_manchester_byte()
{
    int byte = 0;
    for (int i = 7; i >= 0; i--) {
        int bit = Manchester::receive_manchester_bit();
        if (bit == -1) {
            return -1;
        }

        byte = (byte << 1) | bit;
    }
    return byte;
}

void Manchester::send_manchester_bit(int bit)
{
    if (bit == 1) {
        gpio_put(this->tx_pin, 0);
        busy_wait_us(this->clock_period_us / 2);
        gpio_put(this->tx_pin, 1);
    } else {
        gpio_put(this->tx_pin, 1);
        busy_wait_us(this->clock_period_us / 2);
        gpio_put(this->tx_pin, 0);
    }
    busy_wait_us(this->clock_period_us / 2);
}

void Manchester::send_manchester_byte(int byte)
{
    for (int i = 7; i >= 0; i--) {
        int bit = (byte >> i) & 1;
        send_manchester_bit(bit);
    }
}

void Manchester::send_debug_print(uint8_t *frame, size_t length)
{
    string s;
    char hex[4];
    
    for (size_t i = 0; i < length; i++) {
        sprintf(hex, "%02X ", frame[i]);
        s.append(hex);
    }
    printf("Sending frame (hex): %s\n", s.c_str());
}

void Manchester::send_manchester(uint8_t *data, uint32_t length)
{
    vector<uint8_t> frame_with_preamble = add_preamble(data, length);

    for (size_t i = 0; i < frame_with_preamble.size(); i++) {
        send_manchester_byte(frame_with_preamble[i]);
    }
}

vector<uint8_t> Manchester::add_preamble(uint8_t *frame, size_t length)
{
    vector<uint8_t> frame_with_preamble;
    frame_with_preamble.insert(frame_with_preamble.end(), preamble, preamble + PREAMBLE_LEN);
    frame_with_preamble.insert(frame_with_preamble.end(), frame, frame + length);

    return frame_with_preamble;
}

bool Manchester::sync_clock(){
    // Sample first period
    uint64_t start;
    uint64_t end;

    int last = gpio_get(this->rx_pin);
    int now = last;
    
    while(last == now){
        last = now;
        now = gpio_get(this->rx_pin);
    }
    // I discard first edge since it can be cause by data before
    
    last = gpio_get(this->rx_pin);
    while(last == now){
        last = now;
        now = gpio_get(this->rx_pin);
    }
    

    start = to_us_since_boot(get_absolute_time());

    last = gpio_get(this->rx_pin);
    while(last == now){
        last = now;
        now = gpio_get(this->rx_pin);
    }

    end = to_us_since_boot(get_absolute_time()); 

    this->clock_period_us = end - start;
    start = end;
    
    uint8_t expected = (last == 0 && now == 1)? 0 : 1;
    for(int i = 0; i < 7; i++){

        last = gpio_get(this->rx_pin);
        while(last == now){
            last = now;
            now = gpio_get(this->rx_pin);
        }

        end = to_us_since_boot(get_absolute_time());

        this->clock_period_us += end - start;
        this->clock_period_us >>= 1;
        start = end;
        
        if((last == 0 && now == 1) && expected == 0){
            return false;
        }else if((last == 1 && now == 0) && expected == 1){
            return false;
        }

        expected = expected == 1? 0 : 1;
    }

    // This should syncronize me to the begining of the next bit
    busy_wait_us(this->clock_period_us >> 1);
    return true;
}

void Manchester::wait_for_preamble()
{
    // try to sync clock on the preamble
    bool success = false;
    while(!success){
        success = true;
        if(!sync_clock()){
            success = false;
            continue;
        }
        
        int byte = 0;
        while(byte != 0xD5){
            int bit = receive_manchester_bit();
            if(bit == -1){
                success = false;
                break;
            }
            byte = ((byte << 1) | bit) & 0xFF;
        }
    }
}

uint32_t Manchester::recv_manchester(uint8_t *data, uint32_t max_length)
{
    wait_for_preamble();

    for (size_t i = 0; i < max_length; i++) {
        int byte = receive_manchester_byte();
        if (byte == -1) {
            return i;
        }
        data[i] = byte;
    }
    
    return max_length;
}

void Manchester::recv_debug_print(uint8_t *data, uint32_t length)
{
    string s;
    char hex[4];
    
    for (size_t i = 0; i < length; i++) {
        sprintf(hex, "%02X ", data[i]);
        s.append(hex);
    }
    printf("Received frame (hex): %s\n", s.c_str());
}