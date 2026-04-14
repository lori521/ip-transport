# Manchester NonBlock

## Why?

I started rewriting the Manchester encoding algorithm because I wanted to use the full potential of the raspberry pi pico. While trying to write the code for the IP Layer, I kept facing the same problem: How can you do routing with only one device? 

The problem with the previous approach was that Manchester would block waiting for the preamble, which meant you could only have a single receiver

## How?

### GPIO IRQ (Interrupt Request)

GPIO IRQs are hardware signals triggered by specific events, they pause the current code and run a callback function. Why? Originally I did polling on each Manchester interface, but it resulted in timing issues, using interrupts allows me to detect edges as they happen. I mainly use interrupts to detect that a message has started, and to synchronize the clock.

[Example from pico-examples](https://github.com/raspberrypi/pico-examples/blob/master/gpio/hello_gpio_irq/hello_gpio_irq.c)
## Alarms

These are another type of hardware interrupts, they allow me to execute code once every clock period. This is very important for the transmitter, but also for the receiver once the clock has been synchronized

[Example from pico-examples](https://github.com/raspberrypi/pico-examples/blob/master/timer/hello_timer/hello_timer.c)
## State Machine

Because the flow is no longer continuous, I needed to implement a State Machine for both Sender and Receiver:

### RX
1. `IDLE`
   - goes to `SYNC_CLK` once an edge happens
2. `SYNC_CLK`
   - goes to `WAIT_SFD` after a set number of bytes listened
3. `WAIT_SFD`
   - goes to `RECEIVING` on `0xD5`
   - goes to `IDLE` if received invalid data (`0` followed by `0` or `1` followed by `1`)
   - goes to `IDLE` on timeout
4. `RECEIVING`
    - goes to `IDLE` if received invalid data or silence at the end of frame
    - goes to `IDLE` if frame size is too large

### TX
1. `IDLE`
    - goes to `SENDING_PREAMBLE` once there is a frame to send
2. `SENDING_PREAMBLE`
    - goes to `SENDING_DATA` once preamble is done
3. `SENDING_DATA`
    - goes to `SILENCE` once data is done
4. `SILENCE`
    - after waiting a given number of clock periods it goes back to `IDLE`

## Ring Buffer

[What is a ring buffer?](https://en.wikipedia.org/wiki/Circular_buffer)

I started this implementation by using a `queue` to hold the frames I have to send, and I had received.

**Problem**: Heap allocations inside interrupts can cause corruptions, so once every few frames the program died

To avoid using the heap, I implemented a very simple ring buffer

**Decision**: If a ring buffer is full, do you overwrite the old frames or keep them and throw the new ones?

I chose to keep the old packets and throw the new ones, I did not find any specific reference for this problem