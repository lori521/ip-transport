#include "manchester.hpp"

bool Manchester::Read(std::vector<uint8_t> &payload) {
  return this->rx.Read(payload);
}
bool Manchester::Send(std::vector<uint8_t> payload) {
  return this->tx.Send(payload);
}