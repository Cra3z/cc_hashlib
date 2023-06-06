#pragma once
#include "endian.hpp"
namespace ccat {
inline namespace hash {
class md5 {
public:
    using byte = unsigned char;
    static constexpr size_t result_length = 16;//unit: bytes
    md5() = default;
    explicit md5(const std::string& s) : __seq(s.begin(), s.end()) {}
    md5(const md5&) = delete;
    md5(md5&& other): __seq(std::move(other.__seq)) {}
    auto operator=(const md5&) -> md5& = delete;
    auto operator=(md5&& other) -> md5& {
        if (std::addressof(other) != this) {
            __seq = std::move(other.__seq);
        }
        return *this;
    }
    auto digest() -> std::array<uint32_t, 4> {
        __extend_to_little_endian_N512bits();
        std::array<uint32_t, 4> magic_nums{
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
        }, abcd{};
        static std::array<uint32_t, 64> K{
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
        static std::array<size_t, 16> S{
            7, 12, 17, 22,
            5, 9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21
        };
        for (size_t _ = 0; _ < __seq.size() / 64; ++_) {
            abcd = magic_nums;
#if defined(__cplusplus) && __cplusplus >= 201703L || defined(_MSVC_LANG) && _MSVC_LANG >= 201703L
            auto& [a, b, c, d] = abcd;
#else 
            auto &a = abcd[0], &b = abcd[1], &c = abcd[2], &d = abcd[3];
#endif
            for (size_t i = 0; i < 64; ++i) {
                uint32_t F, M;
                size_t cnt, g, offset = _ * 64;
                if (i < 16) 
                    std::tie(cnt, F, g) = std::forward_as_tuple(S[i % 4], (b & c) | ((~b) & d), i);
                else if (i < 32)
                    std::tie(cnt, F, g) = std::forward_as_tuple(S[4 + i % 4], (d & b) | ((~d) & c), (5 * i + 1) % 16);
                else if (i < 48)
                    std::tie(cnt, F, g) = std::forward_as_tuple(S[8 + i % 4], b ^ c ^ d, (3 * i + 5) % 16);
                else
                    std::tie(cnt, F, g) = std::forward_as_tuple(S[12 + i % 4], c ^ (b | (~d)), (7 * i) % 16);
                M = __cvt_byte4_to_uint32_t(&__seq[4 * g + offset]);
                a = a + F + K[i] + M;
                a = ((a << cnt) | (a >> (32 - cnt))) + b;
                auto tmp = d;
                for (auto j = abcd.size() - 1; j > 0; --j) abcd[j] = abcd[j - 1];
                a = tmp;
            }
            for (size_t j = 0; j < 4; ++j) magic_nums[j] += abcd[j];
        }
        return magic_nums;
    }
    auto hexdigest() -> std::string {
        std::stringstream _ss;
        _ss << std::hex;
        auto result = digest();
        std::for_each(result.begin(), result.end(), [&_ss](uint32_t i) -> void {
            for (size_t _{}; _ < 4; ++_) {
                uint16_t tmp = reinterpret_cast<byte*>(&i)[is_little_endian() ? _ : 3-_];
                _ss << (tmp >= 0x10 ? '\0' : '0') << tmp;
            }
        });
        return _ss.str();
    }
    auto update(const std::string& str) -> void {
        std::copy(str.begin(), str.end(), std::back_inserter(__seq));
    }
    auto operator<<(const std::string& str) ->md5& {
        update(str);
        return *this;
    }
    auto operator>>(std::string& str) ->void {
        str = hexdigest();
        clear();
    }
    auto clear() ->void {
        __seq.clear();
    }
    auto empty() ->bool {
        return __seq.empty();
    }
private:
    auto __extend_to_little_endian_N512bits() -> void {
        uint64_t src_size_unit_bits = __seq.size() * 8;
        __seq.emplace_back('\x80');
        size_t insert_0_index = __seq.size();
        auto src_size_ = reinterpret_cast<byte*>(&src_size_unit_bits);
        for (size_t i{}; i < 8; ++i) {
            __seq.emplace_back(src_size_[is_little_endian() ? i : 7-i]);
        }
        while (__seq.size() % 64) {
            __seq.emplace(std::next(__seq.begin(), insert_0_index), '\0');
        }
    }
    // byte[4] as a little endian unsigned int32_t
    // requires `b[i]` [with i = 0, 1, 2, 3] is accessible
    auto __cvt_byte4_to_uint32_t(byte* b) ->uint32_t {
        uint32_t result{0};
        for (size_t i{0}; i < 4; ++i) {
            result += uint32_t(b[i]) << (i*8);
        }
        return result;
    }
    std::vector<byte> __seq{};
};
}
}