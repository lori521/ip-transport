#include "manchester.hpp"
#include "pico/stdlib.h"
#include <cstring>
#include <iostream>

ManchesterTx::ManchesterTx(uint8_t tx_pin, uint64_t clock_period) {
  this->tx_pin = tx_pin;
  gpio_init(this->tx_pin);
  gpio_set_dir(this->tx_pin, GPIO_OUT);

  this->state = ManchesterTxState::IDLE;
  this->state_data.idle = {};

  this->clock_period = clock_period;
  add_alarm_in_us(this->clock_period, transmit_alarm, this, true);
}

long long ManchesterTx::transmit_alarm(alarm_id_t id, void *data) {
  ManchesterTx *tx = (ManchesterTx *)data;
  switch (tx->state) {
  case ManchesterTxState::IDLE: {
    frame_t f;
    if (tx->data.read_frame(f)) {
      tx->state = ManchesterTxState::SENDING_PREAMBLE;
      tx->state_data.send_preamble = {.sent_first_part = false,
                                      .bit_idx = 0,
                                      .byte_idx = 0,
                                      .frame_to_send = f};
    }
    break;
  }
  case ManchesterTxState::SENDING_PREAMBLE: {
    if (tx->state_data.send_preamble.byte_idx < PREAMBLE_SIZE) {
      uint8_t current_byte =
          tx->preamble[tx->state_data.send_preamble.byte_idx];
      bool current_bit =
          (current_byte >> (7 - tx->state_data.send_preamble.bit_idx)) & 1;

      if (!tx->state_data.send_preamble
               .sent_first_part) { // send bit 0 1 for 1, 1 0 for 0
        if (current_bit == 1) {
          gpio_put(tx->tx_pin, 0);
        } else {
          gpio_put(tx->tx_pin, 1);
        }
        tx->state_data.send_preamble.sent_first_part = true;
      } else {
        if (current_bit == 1) {
          gpio_put(tx->tx_pin, 1);
        } else {
          gpio_put(tx->tx_pin, 0);
        }
        tx->state_data.send_preamble.bit_idx++;
        tx->state_data.send_preamble.sent_first_part = false;
        if (tx->state_data.send_preamble.bit_idx == 8) {
          tx->state_data.send_preamble.bit_idx = 0;
          tx->state_data.send_preamble.byte_idx++;
        }
      }
      break;
    } else { // go to SENDING_DATA if preamble done
      tx->state = ManchesterTxState::SENDING_DATA;
      frame_t f = tx->state_data.send_preamble.frame_to_send;
      tx->state_data.send_data = {.sent_first_part = false,
                                  .bit_idx = 0,
                                  .byte_idx = 0,
                                  .current_frame = f};

      // Here I let it fall in the next case
    }
  }
  case ManchesterTxState::SENDING_DATA: {
    if (tx->state_data.send_data.byte_idx >=
        tx->state_data.send_data.current_frame.size) {
      gpio_put(tx->tx_pin, 0);
      tx->state = ManchesterTxState::SILENCE;
      tx->state_data = {
          .silence = {
              .nr_silence = 8, // TODO: Remove this hardcoded value
          }};
      break;
    }

    // same logic as preamble
    uint8_t current_byte = tx->state_data.send_data.current_frame
                               .payload[tx->state_data.send_data.byte_idx];
    bool current_bit =
        (current_byte >> (7 - tx->state_data.send_data.bit_idx)) & 1;

    if (!tx->state_data.send_data.sent_first_part) {
      if (current_bit == 1) {
        gpio_put(tx->tx_pin, 0);
      } else {
        gpio_put(tx->tx_pin, 1);
      }
      tx->state_data.send_data.sent_first_part = true;
    } else {
      if (current_bit == 1) {
        gpio_put(tx->tx_pin, 1);
      } else {
        gpio_put(tx->tx_pin, 0);
      }
      tx->state_data.send_data.bit_idx++;
      tx->state_data.send_data.sent_first_part = false;
      if (tx->state_data.send_data.bit_idx == 8) {
        tx->state_data.send_data.bit_idx = 0;
        tx->state_data.send_data.byte_idx++;
      }
    }
    break;
  }
  case ManchesterTxState::SILENCE: {
    if (tx->state_data.silence.nr_silence > 0) {
      tx->state_data.silence.nr_silence--;
    } else {
      tx->state = ManchesterTxState::IDLE;
      tx->state_data = {};
    }
    break;
  }
  }
  return tx->clock_period >> 1;
}

bool ManchesterTx::Send(std::vector<uint8_t> payload) {
  frame_t f;
  if (payload.size() > MAX_FRAME_SIZE) {
    printf("Payload is too large\n");
    return false;
  }

  f.size = payload.size();
  memcpy(f.payload, payload.data(), payload.size());
  if (!this->data.write_frame(f)) {
    printf("No space available\n");
    return false;
  }

  return true;
}