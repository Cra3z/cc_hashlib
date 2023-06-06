#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <ostream>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace ccat {
auto inline is_little_endian() -> bool {
  uint16_t __i = 0x0100; // 256
  return *reinterpret_cast<unsigned char *>(&__i) == 0;
}
}