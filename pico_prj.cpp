#include "hardware/clocks.h"
#include "hardware/dma.h"
#include "hardware/uart.h"
#include "pico/cyw43_arch.h"
#include "pico/multicore.h"
#include "pico/stdlib.h"
#include "tusb.h"
#include <iostream>
#include <stdio.h>
#include <string>

#include "ethernet/ethernet.hpp"
#include "ip/ip.hpp"
#include "manchester_nonblock/manchester.hpp"
#include "transport/tcp_header.hpp"

// GPIO defines
#define BAUD_RATE 9600
// #define TX_PIN 12
// #define RX_PIN 13

#define TX1_PIN 12
#define RX1_PIN 13

#define TX2_PIN 10
#define RX2_PIN 11

#define CLOCK_PERIOD_US 104

// Ethernet defines
const uint8_t source_mac_address[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
const uint8_t destination_mac_address[] = {0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE};
const uint16_t ether_type = 0x0800;
const size_t MAX_FRAME_SIZE = 1024;

// Data to send
vector<uint8_t> sending_data = {'H', 'e', 'l', 'l', 'o', ' ',
                                'W', 'o', 'r', 'l', 'd', '!'};
uint32_t sending_data_len = sending_data.size();

// IP defines
ipv4_settings_t ip_settings((char *)"192.168.100.1", TCP);
char destination_ip_address[15] = "192.168.100.2";

using namespace std;

void sender(Manchester &manchester) {
  Ethernet ethernet(manchester, source_mac_address);
  
  ipv4_settings_t sender_settings((char*)"192.168.100.1", TCP);
  
  IPv4 ip(ethernet, sender_settings);
  tcp_layer tcp(ip);

  printf("[SENDER] wait 5 seconds before sending SYN...\n");
  sleep_ms(5000);

  bool sender_established = false;
  bool receiver_established = false;

  while(1) {
      printf("\n[SENDER] Begin connection establish...\n");
      
      while (!tcp.establish_connection_sender(destination_ip_address, 8080, 12345)) {
          sleep_ms(1);
      }
        
      printf("\n[SENDER] Connection Established! Begin connection teardown...\n");
      
      while (!tcp.finish_connection_sender(destination_ip_address, 8080, 12345)) {
          sleep_ms(1);
      }
      
      printf("[SENDER] Handshake and Teardown complete. Restarting in 3 seconds...\n");
      sleep_ms(3000);
  }
}

void receiver(Manchester &manchester) {
  Ethernet ethernet(manchester, destination_mac_address);

  ipv4_settings_t receiver_settings((char*)"192.168.100.2", TCP);
  
  IPv4 ip(ethernet, receiver_settings);
  tcp_layer tcp(ip);

  while(1) {
      printf("\n[RECEIVER] Begin connection establish...\n");
      
      while (!tcp.establish_connection_receiver((char*)"192.168.100.1", 12345, 8080)) {
          sleep_ms(1);
      }
        
      printf("\n[RECEIVER] Connection Established! Waiting for connection teardown...\n");
      
      while (!tcp.finish_connection_receiver((char*)"192.168.100.1", 12345, 8080)) {
          sleep_ms(1);
      }
      
      printf("[RECEIVER] Teardown complete. Resetting for next connection...\n");
  }
}

void run_single_core_simulation(Manchester &m_send, Manchester &m_recv) {
  // sender init
  Ethernet eth_send(m_send, source_mac_address);
  ipv4_settings_t set_send((char*)"192.168.100.1", TCP);
  IPv4 ip_send(eth_send, set_send);
  tcp_layer tcp_send(ip_send);

  // recv init
  Ethernet eth_recv(m_recv, destination_mac_address);
  ipv4_settings_t set_recv((char*)"192.168.100.2", TCP);
  IPv4 ip_recv(eth_recv, set_recv);
  tcp_layer tcp_recv(ip_recv);
  tcp_recv.set_simulate_drop(true);

  printf("\n[SIM] begin 3 way handshake\n");
  fflush(stdout); 

  bool sender_established = false;
  bool receiver_established = false;

  while (!sender_established || !receiver_established) {
      if (!sender_established) {
          sender_established = tcp_send.establish_connection_sender(destination_ip_address, 8080, 12345);
      }
      if (!receiver_established) {
          receiver_established = tcp_recv.establish_connection_receiver((char*)"192.168.100.1", 12345, 8080);
      }
      
      sleep_ms(5);
  }

  printf("\n[SIM] begin data transmission\n");
  fflush(stdout);

  // test cwnd
  vector<uint8_t> sending_data(5000, 'A');
  uint32_t sending_data_len = sending_data.size();  

  tcp_send.send_segment(sending_data.data(), sending_data_len);

  uint32_t total_bytes_received = 0;

  while (total_bytes_received < sending_data_len) {
      tcp_send.check_retransmission();
      
      tcp_send.send_segment(nullptr, 0);

      for (int i = 0; i < 10; i++) {
          uint32_t bytes_got = tcp_recv.receive_segment();
          if (bytes_got > 0) {
            total_bytes_received += bytes_got;
            printf("[SIM] receiver got %d bytes!\n", bytes_got);
          }
          tcp_send.receive_segment();
          
          sleep_ms(20);
        }
  }

  uint8_t app_buffer[5000]; 
  uint32_t read_result = tcp_recv.read_data(app_buffer, sending_data_len);
  
  if (read_result > 0) {
      app_buffer[read_result] = '\0';
      printf("[SIM] read %u bytes from buffer\n", read_result);
  }

  fflush(stdout);

  printf("\n[SIM] data transmission complete! Moving to teardown...\n");
  fflush(stdout);

  printf("\n[SIM] begin 4 way handshake\n");
  fflush(stdout);

  bool sender_finished = false;
  bool receiver_finished = false;

  while (!sender_finished || !receiver_finished) {
    if (!sender_finished) {
        sender_finished = tcp_send.finish_connection_sender(destination_ip_address, 8080, 12345);
    }
    if (!receiver_finished) {
        receiver_finished = tcp_recv.finish_connection_receiver((char*)"192.168.100.1", 12345, 8080);
    }
  }

  printf("\n[SIM] all good! ^^\n");
  fflush(stdout);
}


Manchester manchester_sender(RX1_PIN, TX1_PIN, CLOCK_PERIOD_US);
Manchester manchester_receiver(RX2_PIN, TX2_PIN, CLOCK_PERIOD_US);

int main() {
  stdio_init_all();

  while (!stdio_usb_connected()) {
      sleep_ms(100);
  }
  
  // Initialise the Wi-Fi chip
  if (cyw43_arch_init()) {
    printf("Wi-Fi init failed\n");
    return -1;
  }

  // Power on the Wi-Fi LED
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

  // Initialise Manchester

  string type = "test";

  if (type == "sender") {
    //sender(global_manchester);
  } else if (type == "receiver") {
    //receiver(global_manchester);
  } else if (type == "test") {

    printf("[MAIN] simulation on only one pico...\n");

    run_single_core_simulation(manchester_sender, manchester_receiver);

    printf("IT WORKED :))))))))\n");
    
  } else {
    printf("Invalid type. Choose between \"sender\" and \"receiver\" \n");
    return -1;
  }

  while (1) {
      sleep_ms(1000); 
  }

  return 0;
}
