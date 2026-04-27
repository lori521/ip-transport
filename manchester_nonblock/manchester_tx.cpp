#include "hardware/clocks.h"
#include "hardware/dma.h"
#include "manchester.hpp"
#include "manchester_encoding.pio.h"
#include <iostream>
ManchesterTx::ManchesterTx(uint8_t tx_pin, uint64_t clock_period) {
  this->tx_pin = tx_pin;

  pio = pio0; // try this pio block
  sm = pio_claim_unused_sm(pio, false);
  if (sm < 0 || !pio_can_add_program(pio, &manchester_tx_program)) {
    if (sm >= 0) {
      pio_sm_unclaim(pio, sm);
    }
    pio = pio1;
    sm = pio_claim_unused_sm(pio, false);
    if (sm < 0 || !pio_can_add_program(pio, &manchester_tx_program)) {
      printf("Cannot instantiate PIO TX\n");
      return;
    }
  }
  printf("RX-pin%d: pio=%d sm=%d\n", tx_pin, pio == pio0 ? 0 : 1, sm);

  uint offset_rx = pio_add_program(pio, &manchester_tx_program);

  float div =
      clock_get_hz(clk_sys) /
      (1000000.0f / clock_period * 12); // for each bit the PIO has 12 cicles

  manchester_tx_program_init(pio, sm, offset_rx, this->tx_pin, div);

  dma_chan = dma_claim_unused_channel(true);
}
bool ManchesterTx::Send(std::vector<uint8_t> payload) {
  std::vector<uint8_t> start_frame(preamble, preamble + PREAMBLE_SIZE);
  start_frame.push_back(DEL);
  start_frame.push_back(SFD);

  payload.insert(payload.begin(), start_frame.begin(), start_frame.end());

  payload.push_back(DEL);
  payload.push_back(EFD);

  dma_channel_config c = dma_channel_get_default_config(dma_chan);

  channel_config_set_transfer_data_size(&c, DMA_SIZE_8);
  channel_config_set_read_increment(&c, true);
  channel_config_set_write_increment(&c, false);
  channel_config_set_dreq(&c, pio_get_dreq(this->pio, sm, true));

  dma_channel_configure(dma_chan, &c,
                        (volatile uint8_t *)&this->pio->txf[sm] + 3,
                        payload.data(), payload.size(), true);
  dma_channel_wait_for_finish_blocking(dma_chan);

  return true;
}
ManchesterTx::~ManchesterTx() {
  pio_sm_set_enabled(pio, sm, false);
  pio_sm_unclaim(pio, sm);
  dma_channel_abort(dma_chan);
  dma_channel_unclaim(dma_chan);
}