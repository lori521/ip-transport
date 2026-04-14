#include "manchester.hpp"
#include <iostream>

ManchesterRx *rxs[MAX_PIN + 1]; // I need this global, because i route callback
                                // based on it

void gpio_callback(uint gpio, uint32_t events) {
  if (rxs[gpio]) {
    rxs[gpio]->edge_callback();
  }
}

ManchesterRx::ManchesterRx(uint8_t rx_pin) {
  this->rx_pin = rx_pin;
  gpio_init(this->rx_pin);
  gpio_set_dir(this->rx_pin, GPIO_IN);

  gpio_set_irq_enabled_with_callback(this->rx_pin,
                                     GPIO_IRQ_EDGE_RISE | GPIO_IRQ_EDGE_FALL,
                                     true, gpio_callback);

  this->state = ManchesterRxState::IDLE;
  this->state_data.idle = {};

  rxs[this->rx_pin] = this;

  gpio_pull_down(this->rx_pin); // ignore random noise
}

long long ManchesterRx::handle_receive_alarm(alarm_id_t id, void *data) {
  ManchesterRx *rx = (ManchesterRx *)data;

  bool sample = gpio_get(rx->rx_pin);
  if (rx->state_data.receive.last_sample != -1) { // already measure once
    if (rx->state_data.receive.last_sample == 0 && sample == 1) { // received 1
      rx->state_data.receive.current_byte <<= 1;
      rx->state_data.receive.current_byte |= 1;
    } else if (rx->state_data.receive.last_sample == 1 &&
               sample == 0) { // received 0
      rx->state_data.receive.current_byte <<= 1;
    } else { // if 0 0 or 1 1 probably at the end, or corrupted so renter IDLE
      rx->data.write_frame(rx->state_data.receive.current_frame);

      rx->state = ManchesterRxState::IDLE;
      rx->state_data.idle = {};
      gpio_set_irq_enabled(rx->rx_pin, GPIO_IRQ_EDGE_RISE | GPIO_IRQ_EDGE_FALL,
                           true);
      return 0;
    }

    rx->state_data.receive.last_sample = -1;
    rx->state_data.receive.bit_idx++;

    if (rx->state_data.receive.bit_idx == 8) {
      if (!rx->state_data.receive.current_frame.push(
              rx->state_data.receive
                  .current_byte)) { // if fail to write to frame, throw packet
                                    // and renter IDLE
        printf("Frame size is too large, throwed packet\n");

        rx->state = ManchesterRxState::IDLE;
        rx->state_data.idle = {};
        gpio_set_irq_enabled(rx->rx_pin,
                             GPIO_IRQ_EDGE_RISE | GPIO_IRQ_EDGE_FALL, true);
        return 0;
      }

      rx->state_data.receive.bit_idx = 0;
      rx->state_data.receive.current_byte = 0;
    }
  } else {
    rx->state_data.receive.last_sample = sample;
  }
  return rx->clock_period >> 1;
}

long long ManchesterRx::handle_sfd_alarm(alarm_id_t id, void *data) {
  ManchesterRx *rx = (ManchesterRx *)data;

  bool sample = gpio_get(rx->rx_pin);
  if (rx->state_data.wait_sfd.last_sample != -1) {
    if (rx->state_data.wait_sfd.last_sample == 0 && sample == 1) { // 1
      rx->state_data.wait_sfd.current_byte <<= 1;
      rx->state_data.wait_sfd.current_byte |= 1;
    } else if (rx->state_data.wait_sfd.last_sample == 1 && sample == 0) { // 0
      rx->state_data.wait_sfd.current_byte <<= 1;
    } else { // if 0 0 or 1 1 data is corrupted, renter IDLE
      printf("Error while waiting for SFD\n");
      rx->state = ManchesterRxState::IDLE;
      rx->state_data.idle = {};
      gpio_set_irq_enabled(rx->rx_pin, GPIO_IRQ_EDGE_RISE | GPIO_IRQ_EDGE_FALL,
                           true);
      return 0;
    }

    // Same as receiving data, but on 0xD5 change state
    rx->state_data.wait_sfd.last_sample = -1;
    rx->state_data.wait_sfd.bit_idx++;
    if (rx->state_data.wait_sfd.bit_idx == 8) {
      if (rx->state_data.wait_sfd.current_byte == 0xD5) {
        rx->state = ManchesterRxState::RECEIVING;
        rx->state_data.receive = {.last_sample = -1,
                                  .bit_idx = 0,
                                  .current_byte = 0,
                                  .current_frame = frame_t{.size = 0}};
        add_alarm_in_us(rx->clock_period >> 1, handle_receive_alarm, rx, true);
        return 0;
      }

      rx->state_data.wait_sfd.bit_idx = 0;
      rx->state_data.wait_sfd.current_byte = 0;
      rx->state_data.wait_sfd.nr_samples++;

      if (rx->state_data.wait_sfd.nr_samples == PREAMBLE_SIZE) {
        printf("Timeout while waiting for SFD\n");
        rx->state = ManchesterRxState::IDLE;
        rx->state_data.idle = {};
        gpio_set_irq_enabled(rx->rx_pin,
                             GPIO_IRQ_EDGE_RISE | GPIO_IRQ_EDGE_FALL, true);
        return 0;
      }
    }
  } else {
    rx->state_data.wait_sfd.last_sample = sample;
  }
  return rx->clock_period >> 1;
}

void ManchesterRx::edge_callback() {
  switch (this->state) {
  case ManchesterRxState::IDLE: {
    this->state = ManchesterRxState::SYNC_CLK;
    this->state_data.sync_clk.nr_edges = 0;
    this->state_data.sync_clk.last_edge = 0; // ignore first edge;
    this->clock_period = 0;

    break;
  }
  case ManchesterRxState::SYNC_CLK: {
    if (this->state_data.sync_clk.last_edge == 0) {
      this->state_data.sync_clk.last_edge =
          to_us_since_boot(get_absolute_time());
      this->state_data.sync_clk.nr_edges = 1;
    } else {
      uint64_t timestamp = to_us_since_boot(get_absolute_time());
      uint64_t period = timestamp - this->state_data.sync_clk.last_edge;
      if (this->clock_period == 0) {
        this->clock_period = period;
      } else {
        this->clock_period = (this->clock_period + period) >> 1;
      }
      this->state_data.sync_clk.last_edge = timestamp;
      this->state_data.sync_clk.nr_edges++;
    }

    if (this->state_data.sync_clk.nr_edges == 32) {
      this->state = ManchesterRxState::WAIT_SFD;

      this->state_data.wait_sfd = {
          .last_sample = -1,
          .bit_idx = 0,
          .current_byte = 0,
          .nr_samples = 0,
      };

      add_alarm_in_us(this->clock_period >> 1, handle_sfd_alarm, this, true);
      gpio_set_irq_enabled(this->rx_pin,
                           GPIO_IRQ_EDGE_RISE | GPIO_IRQ_EDGE_FALL, false);
    }
    break;
  }
  default: {
    break; // once the clock is sync'd we do not rely on the
           // edge_callback
  }
  }
}

bool ManchesterRx::Read(std::vector<uint8_t> &payload) {
  frame_t f;
  if (!this->data.read_frame(f)) {
    return false;
  }
  payload = std::vector<uint8_t>(f.payload, f.payload + f.size);
  return true;
}