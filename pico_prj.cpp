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
  IPv4Sender ip(ip_settings);

  Ethernet ethernet;
  ethernet.init(source_mac_address, destination_mac_address, ether_type);

  while (1) {
    ipv4_packet_batch_t batch;
    if (ip.GeneratePackets(sending_data, destination_ip_address, batch) !=
        true) {
      printf("Could not generate packets\n");
      continue;
    }

    for (auto packet : batch.ipv4_packets) {
      // Encapsulate the payload into an Ethernet frame
      vector<uint8_t> ip_payload = packet.dump_network_packet();
      vector<uint8_t> frame =
          ethernet.eth_encap(ip_payload.data(), ip_payload.size());

      // DEBUG: printing the frame
      manchester.send_debug_print(frame.data(), frame.size());

      // Send the frame
      manchester.send_manchester(frame.data(), frame.size());

      sleep_ms(250);
    }
  }
}

void receiver(Manchester &manchester) {
  IPv4Receiver ip(ip_settings);
  Ethernet ethernet;
  ethernet.init(destination_mac_address, source_mac_address, ether_type);

  while (1) {
    // Expecting the same byte payload as the sender
    uint8_t frame[MAX_FRAME_SIZE];

    memset(frame, 0, sizeof(frame));

    // Receive the frame
    uint32_t frame_len = manchester.recv_manchester(frame, MAX_FRAME_SIZE);

    // DEBUG: printing the frame
    manchester.recv_debug_print(frame, frame_len);

    vector<uint8_t> decap_frame = ethernet.eth_decap(frame, frame_len);
    if (decap_frame.size() == 0) {
      continue;
    }

    ip.ReadPackets(decap_frame);

    for (auto batch : ip.PopFinishedBatch()) {
      vector<uint8_t> message;
      batch.get_payload(message);

      char src_addr[16];
      encode_ip_address(batch.ipv4_packets.begin()->header.source_ip_address,
                        src_addr);
      printf("Received message from ip address %s: ", src_addr);
      for (size_t i = 0; i < message.size(); i++) {
        printf("%c", message[i]);
      }
      printf("\n");
    }
  }
}

int main() {
  stdio_init_all();

  // Initialise the Wi-Fi chip
  if (cyw43_arch_init()) {
    printf("Wi-Fi init failed\n");
    return -1;
  }

  // Power on the Wi-Fi LED
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

  // Initialise Manchester
  Manchester manchester;
  manchester.init(TX_PIN, RX_PIN, BAUD_RATE, CLOCK_PERIOD_US);

  string type = "test";

  if (type == "sender") {
    sender(manchester);
  } else if (type == "receiver") {
    receiver(manchester);
  } else if (type == "test") {

    multicore_launch_core1([]() {
      Manchester manchester;
      manchester.init(TX_PIN, RX_PIN, BAUD_RATE, CLOCK_PERIOD_US);
      sender(manchester);
    });

    receiver(manchester);
  } else {
    printf("Invalid type. Choose between \"sender\" and \"receiver\" \n");
    return -1;
  }

  return 0;
}
