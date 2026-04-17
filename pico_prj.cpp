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
#include "manchester_codec/manchester.hpp"
#include "transport/tcp_header.hpp"

// GPIO defines
#define BAUD_RATE 9600
#define TX_PIN 12
#define RX_PIN 13
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
ipv4_settings_t ip_settings("192.168.100.1", TCP);
char destination_ip_address[15] = "192.168.100.2";

using namespace std;

void sender(Manchester &manchester) {

  Ethernet ethernet;
  ethernet.init(source_mac_address, destination_mac_address, ether_type);
  
  ipv4_settings_t sender_settings("192.168.100.1", TCP);
  IPv4 ip(manchester, ethernet, sender_settings);

  tcp_layer tcp(ip);

  printf("[SENDER] wait 5 seconds before sending SYN...\n");
  sleep_ms(5000);

  sleep_ms(500);

  while(1) {
    printf("\n[SENDER] Begin connection establish...\n");
      if (tcp.establish_connection_sender(destination_ip_address, 8080, 12345)) {
        
        printf("\n[SENDER] Begin connection teardown...\n");
        tcp.finish_connection_sender(destination_ip_address, 8080, 12345);
        
      } else {
        printf("[SENDER] Handshake failed!\n");
      }
  }
  printf("[SENDER] Core 1 finished execution.\n");
}

void receiver(Manchester &manchester) {
  Ethernet ethernet;
  ethernet.init(destination_mac_address, source_mac_address, ether_type);

  ipv4_settings_t receiver_settings("192.168.100.2", TCP);
  IPv4 ip(manchester, ethernet, receiver_settings);

  tcp_layer tcp(ip);

  while(1) {
    printf("\n[RECEIVER] Begin connection establish...\n");
    if (tcp.establish_connection_receiver((char*)"192.168.100.1", 12345, 8080)) {
        
        printf("\n[RECEIVER] Waiting for connection teardown...\n");
        tcp.finish_connection_receiver((char*)"192.168.100.1", 12345, 8080);

    } else {
        printf("[RECEIVER] Handshake failed!\n");
    }
  }

  printf("[RECEIVER] Core 0 finished execution.\n");
}

Manchester global_manchester;

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
  global_manchester.init(TX_PIN, RX_PIN, BAUD_RATE, CLOCK_PERIOD_US);

  string type = "sender";

  if (type == "sender") {
    sender(global_manchester);
  } else if (type == "receiver") {
    receiver(global_manchester);
  } else if (type == "test") {

    multicore_launch_core1([]() {
      sender(global_manchester);
    });
    receiver(global_manchester);
  } else {
    printf("Invalid type. Choose between \"sender\" and \"receiver\" \n");
    return -1;
  }

  while (1) {
      sleep_ms(1000); 
  }

  return 0;
}
