#include "hardware/clocks.h"
#include "hardware/dma.h"
#include "hardware/pio.h"
#include "manchester.hpp"
#include "manchester_encoding.pio.h"
#include "pico/stdlib.h"
#include <iostream>

ManchesterRx::ManchesterRx(uint8_t rx_pin, uint64_t clock_period) {
  this->rx_pin = rx_pin;

  PIO pio = pio0; // try this pio block
  if (!pio_can_add_program(pio, &manchester_rx_program)) {
    pio = pio1;
    if (!pio_can_add_program(pio, &manchester_rx_program)) { // try the other
      printf("Cannot instantiate PIO RX");
      return;
    }
  }

  uint offset_rx = pio_add_program(pio, &manchester_rx_program);

  uint sm = pio_claim_unused_sm(pio, true);

  float div =
      clock_get_hz(clk_sys) /
      (1000000.0f / clock_period * 12); // for each bit the PIO has 12 cicles

  manchester_rx_program_init(pio, sm, offset_rx, this->rx_pin, div);

  int chan = dma_claim_unused_channel(true);

  dma_channel_config c = dma_channel_get_default_config(chan);
  channel_config_set_transfer_data_size(&c, DMA_SIZE_8);
  channel_config_set_read_increment(&c, false);
  channel_config_set_write_increment(&c, true);
  channel_config_set_dreq(&c, pio_get_dreq(pio, sm, false));

  channel_config_set_ring(&c, true,
                          10); // make this a ring buffer 2^10 = RING_BUFFER_SIZE
  dma_channel_configure(chan, &c, this->buffer, (uint8_t *)&pio->rxf[sm] + 3,
                        -1, true);

  this->dma_chan = chan;

  gpio_pull_down(rx_pin);
}

uint ManchesterRx::buffer_size() {
  uint write_pos = (uint)dma_channel_hw_addr(this->dma_chan)->write_addr -
                   (uint)this->buffer;
  if (write_pos >= read_pos) {
    return write_pos - read_pos;
  } else {
    return RX_BUFFER_SIZE - read_pos + write_pos;
  }
}
bool ManchesterRx::Read(std::vector<uint8_t> &payload) {
  payload.clear();

  uint initial_read_pos = read_pos;

  while (buffer_size() > 0) {
    uint8_t sample = this->buffer[read_pos];
    if (sample == SFD) {
      // printf("Found sfd\n");
      read_pos = (read_pos + 1) % RX_BUFFER_SIZE;

      uint bytes_read = 0;
      while (buffer_size() > 0 && bytes_read++ < RX_BUFFER_SIZE) {
        sample = this->buffer[read_pos];
        if (sample == EFD) {
          // printf("Ended\n");
          read_pos = (read_pos + 1) % RX_BUFFER_SIZE;
          return true;
        }

        payload.push_back(sample);
        read_pos = (read_pos + 1) % RX_BUFFER_SIZE;
      }

      if (bytes_read >= RX_BUFFER_SIZE) {
        payload.clear();
        return false;
      }

      read_pos = initial_read_pos;
      payload.clear();
      return false;
    } else {
      read_pos = (read_pos + 1) % RX_BUFFER_SIZE;
    }
  }
  return false;
}