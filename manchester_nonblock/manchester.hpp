#pragma once

#include "pico/critical_section.h"
#include "pico/stdlib.h"
#include "ring_buffer.hpp"

#include <cstdint>
#include <queue>
#include <vector>

#define MAX_PIN 30
const uint PREAMBLE_SIZE = 6;
enum class ManchesterRxState { IDLE, SYNC_CLK, WAIT_SFD, RECEIVING };

class ManchesterRx {
  uint8_t rx_pin;
  uint64_t clock_period;
  ManchesterRxState state;

  ring_buffer_t data;
  union {
    struct {
    } idle; // IDLE needs nothing
    struct {
      uint32_t nr_edges;
      uint64_t last_edge;
    } sync_clk;
    struct {
      int last_sample;
      uint bit_idx;
      uint current_byte;
      uint nr_samples;
    } wait_sfd;
    struct {
      int last_sample;
      uint bit_idx;
      uint current_byte;
      frame_t current_frame;
    } receive;
  } state_data;

  static long long handle_receive_alarm(alarm_id_t id, void *data);
  static long long handle_sfd_alarm(alarm_id_t id, void *data);

public:
  void edge_callback();

  ManchesterRx(uint8_t rx_pin);
  bool Read(std::vector<uint8_t> &payload);
};

enum class ManchesterTxState {
  IDLE,
  SENDING_PREAMBLE,
  SENDING_DATA,
  SILENCE,
};

class ManchesterTx {
  uint8_t tx_pin;
  uint64_t clock_period;
  ManchesterTxState state;

  ring_buffer_t data;

  const uint8_t preamble[PREAMBLE_SIZE] = {0x55, 0x55, 0x55, 0x55, 0x55, 0xD5};
  union {
    struct {

    } idle;
    struct {
      bool sent_first_part;
      uint bit_idx;
      uint byte_idx;
      frame_t frame_to_send;
    } send_preamble;
    struct {
      bool sent_first_part;
      uint bit_idx;
      uint byte_idx;
      frame_t current_frame;
    } send_data;
    struct {
      uint nr_silence;
    } silence;
  } state_data;

  static long long transmit_alarm(alarm_id_t id, void *data);

public:
  ManchesterTx(uint8_t tx_pin, uint64_t clock_period);
  bool Send(std::vector<uint8_t> payload);
};

class Manchester {
  ManchesterRx rx;
  ManchesterTx tx;

public:
  Manchester(uint8_t rx_pin, uint8_t tx_pin, uint64_t tx_clock_period)
      : rx(rx_pin), tx(tx_pin, tx_clock_period) {}

public:
  bool Read(std::vector<uint8_t> &payload);
  bool Send(std::vector<uint8_t> payload);
};