#pragma once

#include <cstdint>

// All roads lead to ring buffer :(
#define MAX_FRAME_SIZE 128
struct frame_t {
  uint8_t payload[MAX_FRAME_SIZE];
  uint32_t size;

  bool push(uint8_t byte);
};

#define MAX_NR_FRAMES 8
struct ring_buffer_t {
  frame_t frames[MAX_NR_FRAMES];
  volatile uint32_t
      read_idx; // made volatile because of interrupts (kept crashing, because
                // compiler may optimize out some reads)
  volatile uint32_t write_idx;

  ring_buffer_t();

  bool read_frame(frame_t &f);
  bool write_frame(frame_t f);
};
