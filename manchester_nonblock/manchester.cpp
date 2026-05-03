#include "manchester.hpp"
#include <iostream>
#include <string>

void print_payload(std::vector<uint8_t> &payload) {
  std::string s;
  char hex[4];

  for (size_t i = 0; i < payload.size(); i++) {
    sprintf(hex, "%02X ", payload[i]);
    s.append(hex);
  }
  printf("Frame (hex): %s\n", s.c_str());
}

bool Manchester::Read(std::vector<uint8_t> &payload) {
  bool success = this->rx.Read(payload);
  if (this->debug && success) {
    printf("Reading ");
    print_payload(payload);
  }
  return success;
}
bool Manchester::Send(std::vector<uint8_t> payload) {
  bool success = this->tx.Send(payload);
  if (this->debug && success) {
    printf("Sending ");
    print_payload(payload);
  }
  return success;
}
bool Manchester::Peek(std::vector<uint8_t> &payload) {
  return this->rx.Peek(payload);
}