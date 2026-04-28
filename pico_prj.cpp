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

#define TX1_PIN 12
#define RX1_PIN 13

#define ROUTER_TX_PIN_1 10
#define ROUTER_RX_PIN_1 11

#define ROUTER_TX_PIN_2 8
#define ROUTER_RX_PIN_2 9

#define TX2_PIN 6
#define RX2_PIN 7

#define CLOCK_PERIOD_US 104

// Ethernet defines
const uint8_t source_mac_address[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
const uint8_t router_mac_address[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCD, 0xBE};
const uint8_t destination_mac_address[] = {0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE};
const uint16_t ether_type = 0x0800;
const size_t MAX_FRAME_SIZE = 1024;

// Data to send
vector<uint8_t> sending_data = {'H', 'e', 'l', 'l', 'o', ' ',
                                'W', 'o', 'r', 'l', 'd', '!'};
uint32_t sending_data_len = sending_data.size();

// IP defines
char source_ip_address[15] = "192.168.100.2";
char destination_ip_address[15] = "192.168.100.3";
char router_ip_address[15] = "192.168.100.1";

using namespace std;

void sender() {
  Manchester manchester_sender(RX1_PIN, TX1_PIN, CLOCK_PERIOD_US, true);
  Ethernet eth_send(manchester_sender, source_mac_address);
  ipv4_settings_t set_send(source_ip_address, TCP);
  IPv4Router router_send(router_ip_address, &eth_send);
  ARP arp_send(source_mac_address, source_ip_address);
  IPv4 ip_send(arp_send, router_send, set_send);
  tcp_layer tcp(ip_send);
  printf("Set up sender\n");
  fflush(stdout);

  printf("[SENDER] wait 5 seconds before sending SYN...\n");
  sleep_ms(5000);

  while (1) {
    printf("\n[SENDER] Begin connection establish...\n");

    while (
        !tcp.establish_connection_sender(destination_ip_address, 8080, 12345)) {
      sleep_ms(1);
    }

    printf("\n[SENDER] Connection Established! Begin connection teardown...\n");

    while (!tcp.finish_connection_sender(destination_ip_address, 8080, 12345)) {
      sleep_ms(1);
    }

    printf("[SENDER] Handshake and Teardown complete. Restarting in 3 "
           "seconds...\n");
    sleep_ms(3000);
  }
}
void router() {
  // router init
  Manchester m1_router(ROUTER_RX_PIN_1, ROUTER_TX_PIN_1, CLOCK_PERIOD_US);
  Manchester m2_router(ROUTER_RX_PIN_2, ROUTER_TX_PIN_2, CLOCK_PERIOD_US);
  Ethernet eth_router_1(m1_router, router_mac_address);
  Ethernet eth_router_2(m2_router, router_mac_address);
  ipv4_settings_t set_router((char *)router_ip_address, TCP);

  IPv4Router router;
  router.AddFullEntry(destination_ip_address, &eth_router_2);
  router.AddFullEntry(source_ip_address, &eth_router_1);

  ARP arp_router(router_mac_address, router_ip_address);
  IPv4 ip_router(arp_router, router, set_router);
  printf("Set up router\n");
  fflush(stdout);

  vector<uint8_t> data;
  while (1) {
    ip_router.ReadIPPacket(data, NULL);
  }
}
void receiver() {
  Manchester manchester_receiver(RX2_PIN, TX2_PIN, CLOCK_PERIOD_US, true);
  Ethernet eth_recv(manchester_receiver, destination_mac_address);
  ipv4_settings_t set_recv(destination_ip_address, TCP);
  IPv4Router router_recv(router_ip_address, &eth_recv);
  ARP arp_recv(destination_mac_address, destination_ip_address);
  IPv4 ip_recv(arp_recv, router_recv, set_recv);
  tcp_layer tcp(ip_recv);
  printf("Set up receiver\n");
  fflush(stdout);

  while (1) {
    printf("\n[RECEIVER] Begin connection establish...\n");

    while (!tcp.establish_connection_receiver((char *)router_ip_address, 12345,
                                              8080)) {
      sleep_ms(1);
    }

    printf("\n[RECEIVER] Connection Established! Waiting for connection "
           "teardown...\n");

    while (!tcp.finish_connection_receiver((char *)router_ip_address, 12345,
                                           8080)) {
      sleep_ms(1);
    }

    printf("[RECEIVER] Teardown complete. Resetting for next connection...\n");
  }
}

void run_single_core_simulation() {
  // sender init
  Manchester manchester_sender(RX1_PIN, TX1_PIN, CLOCK_PERIOD_US, true);
  Ethernet eth_send(manchester_sender, source_mac_address);
  ipv4_settings_t set_send(source_ip_address, TCP);
  IPv4Router router_send(router_ip_address, &eth_send);
  ARP arp_send(source_mac_address, source_ip_address);
  IPv4 ip_send(arp_send, router_send, set_send);
  tcp_layer tcp_send(ip_send);
  printf("Set up sender\n");
  fflush(stdout);

  // recv init
  Manchester manchester_receiver(RX2_PIN, TX2_PIN, CLOCK_PERIOD_US, true);
  Ethernet eth_recv(manchester_receiver, destination_mac_address);
  ipv4_settings_t set_recv(destination_ip_address, TCP);
  IPv4Router router_recv(router_ip_address, &eth_recv);
  ARP arp_recv(destination_mac_address, destination_ip_address);
  IPv4 ip_recv(arp_recv, router_recv, set_recv);
  tcp_layer tcp_recv(ip_recv);
  printf("Set up receiver\n");
  fflush(stdout);

  // router init
  Manchester m1_router(ROUTER_RX_PIN_1, ROUTER_TX_PIN_1, CLOCK_PERIOD_US);
  Manchester m2_router(ROUTER_RX_PIN_2, ROUTER_TX_PIN_2, CLOCK_PERIOD_US);
  Ethernet eth_router_1(m1_router, router_mac_address);
  Ethernet eth_router_2(m2_router, router_mac_address);
  ipv4_settings_t set_router((char *)router_ip_address, TCP);

  IPv4Router router;
  router.AddFullEntry(destination_ip_address, &eth_router_2);
  router.AddFullEntry(source_ip_address, &eth_router_1);

  ARP arp_router(router_mac_address, router_ip_address);
  IPv4 ip_router(arp_router, router, set_router);
  printf("Set up router\n");
  fflush(stdout);

  vector<uint8_t> data;

  printf("\n[SIM] begin 3 way handshake\n");
  fflush(stdout);

  bool sender_established = false;
  bool receiver_established = false;

  while (!sender_established || !receiver_established) {

    if (!sender_established) {
      sender_established = tcp_send.establish_connection_sender(
          destination_ip_address, 8080, 12345);
    }

    ip_router.ReadIPPacket(data, NULL);

    if (!receiver_established) {
      receiver_established = tcp_recv.establish_connection_receiver(
          (char *)source_ip_address, 12345, 8080);
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

    ip_router.ReadIPPacket(data, NULL);

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
      sender_finished = tcp_send.finish_connection_sender(
          destination_ip_address, 8080, 12345);
    }
    ip_router.ReadIPPacket(data, NULL);
    if (!receiver_finished) {
      receiver_finished =
          tcp_recv.finish_connection_receiver(source_ip_address, 12345, 8080);
    }
  }

  sleep_ms(50);
  printf("\n[SIM] all good! ^^\n");
  fflush(stdout);
}

int main() {
  stdio_init_all();

  while (!stdio_usb_connected()) {
    sleep_ms(100);
  }

  printf("clk_sys = %u Hz\n", clock_get_hz(clk_sys));
  float div = clock_get_hz(clk_sys) / (1000000.0f / 104 * 12);
  printf("PIO div = %f\n", div);
  printf("Actual baud = %f Hz\n", clock_get_hz(clk_sys) / div);

  // Initialise the Wi-Fi chip
  // if (cyw43_arch_init()) {
  //   printf("Wi-Fi init failed\n");
  //   return -1;
  // }

  // Power on the Wi-Fi LED
  // cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

  // Initialise Manchester

  string type = "router";

  if (type == "sender") {
    sender();
  } else if (type == "receiver") {
    receiver();
  } else if (type == "router") {
    router();
  } else if (type == "test") {

    printf("[MAIN] simulation on only one pico...\n");

    run_single_core_simulation();

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
