#pragma once

#include "hardware/pio.h"
#include "pico/stdlib.h"
#include <cstdint>
#include <queue>
#include <vector>

#define SFD 0x7E
#define EFD 0x81
#define DEL 0xFC

#define PREAMBLE_BYTE 0xAA

const uint PREAMBLE_SIZE = 6;
enum class ManchesterRxState { IDLE, SYNC_CLK, WAIT_SFD, RECEIVING };

#define RX_BUFFER_SIZE 128 // must be 2^n
class ManchesterRx {
  uint8_t rx_pin;
  int dma_chan;

  uint8_t buffer[RX_BUFFER_SIZE] __attribute__((aligned(RX_BUFFER_SIZE)));
  uint read_pos = 0;

  uint buffer_size();

public:
  ManchesterRx(uint8_t rx_pin, uint64_t clock_period_us);
  bool Read(std::vector<uint8_t> &payload);
};

class ManchesterTx {
  uint8_t tx_pin;
  uint64_t clock_period;

  PIO pio;
  uint sm;
  int dma_chan;

  const uint8_t preamble[PREAMBLE_SIZE] = {PREAMBLE_BYTE, PREAMBLE_BYTE,
                                           PREAMBLE_BYTE, PREAMBLE_BYTE,
                                           PREAMBLE_BYTE, PREAMBLE_BYTE};

public:
  ManchesterTx(uint8_t tx_pin, uint64_t clock_period);
  bool Send(std::vector<uint8_t> payload);
};

class Manchester {
  ManchesterRx rx;
  ManchesterTx tx;

public:
  Manchester(uint8_t rx_pin, uint8_t tx_pin, uint64_t clock_period)
      : rx(rx_pin, clock_period), tx(tx_pin, clock_period) {}

public:
  bool Read(std::vector<uint8_t> &payload);
  bool Send(std::vector<uint8_t> payload);
};