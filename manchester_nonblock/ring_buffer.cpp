#include "ring_buffer.hpp"
#include <iostream>

bool frame_t::push(uint8_t byte) {
  if (this->size == MAX_FRAME_SIZE) {
    return false;
  }

  this->payload[this->size++] = byte;
  return true;
}

ring_buffer_t::ring_buffer_t() {
  this->read_idx = 0;
  this->write_idx = 0;
}

bool ring_buffer_t::read_frame(frame_t &f) {
  if (this->read_idx == this->write_idx) {
    return false;
  }

  f = this->frames[this->read_idx];
  this->read_idx = (this->read_idx + 1) % MAX_NR_FRAMES;

  return true;
}
bool ring_buffer_t::write_frame(frame_t f) {
  if ((this->write_idx + 1) % MAX_NR_FRAMES == this->read_idx) {
    return false;
  }
  this->frames[this->write_idx] = f;
  this->write_idx = (this->write_idx + 1) % MAX_NR_FRAMES;

  return true;
}
