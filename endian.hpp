#pragma once

#ifdef CCAT_BUILD_MODULE
#define CCAT_MOD_EXPORT export
#define CCAT_MOD_EXPORT_BEGIN export {
#define CCAT_MOD_EXPORT_END }

import std;

#else
#define CCAT_MOD_EXPORT
#define CCAT_MOD_EXPORT_BEGIN
#define CCAT_MOD_EXPORT_END

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

#endif

CCAT_MOD_EXPORT namespace ccat {

	using std::uint16_t;
	using std::uint32_t;
	using std::uint64_t;
	using std::size_t;
	
	auto inline is_little_endian() -> bool {
	  uint16_t __i = 0x0100; // 256
	  return *reinterpret_cast<unsigned char *>(&__i) == 0;
	}

}
