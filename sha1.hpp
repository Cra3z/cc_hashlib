#pragma once
#include "endian.hpp"
namespace ccat {
inline namespace hash {
class sha1 {
public:
    using byte = unsigned char;
    static constexpr size_t result_length = 20;//unit: bytes
    sha1() = default;
    explicit sha1(const std::string& str) : __seq(str.begin(), str.end()) {}
    sha1(const sha1&) = delete;
    sha1(sha1&& other) : __seq(std::move(other.__seq)) {}
    auto operator= (const sha1& other) = delete;
    auto operator= (sha1&& other) ->sha1& {
        if (std::addressof(other) != this) {
            __seq = std::move(other.__seq);
        }
        return *this;
    } 
    auto update(const std::string& str) ->void {
        std::copy(str.begin(), str.end(), std::back_inserter(__seq));
    }
    auto digest() -> std::array<uint32_t, 5> {
        __extend_to_big_endian_N512bits();
        std::array<uint32_t, 5> magic_nums{
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
        }, abcde{};
        for (size_t _{}; _ < __seq.size() / 64; ++_) {
            size_t offset = _ * 64;
            auto _extent_seq_chunk = __extend_64bytes_to_320bytes(offset);
            abcde = magic_nums;
#if defined(__cplusplus) && __cplusplus >= 201703L || defined(_MSVC_LANG) && _MSVC_LANG >= 201703L
            auto& [a, b, c, d, e] = abcde;
#else
            auto &a = abcde[0], &b = abcde[1], &c = abcde[2], &d = abcde[3], &e = abcde[4];
#endif
            for (size_t i{}; i < 80; ++i) {
                uint32_t f, k, w = __cvt_byte4_to_uint32_t(&_extent_seq_chunk[i*4]);
                if (i < 20) {
                    f = d ^ (b & (c ^ d));
                    k = 0x5a827999;
                }
                else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ed9eba1;
                }
                else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8f1bbcdc;
                }
                else {
                    f  = b ^ c ^ d;
                    k = 0xca62c1d6;
                }
                uint32_t lshift_a_5 = (a << 5) | (a >> (32 - 5));
                e = lshift_a_5 + f + e + k + w;
                b = (b << 30) | (b >> (32 - 30));
                auto tmp = e;
                for (size_t j{4}; j > 0; --j) abcde[j] = abcde[j - 1];
                a = tmp;
            }
            for (size_t j{}; j < 5; ++j) magic_nums[j] += abcde[j];
        }
        return magic_nums;
    }
    auto hexdigest() ->std::string {
        std::stringstream _ss;
        _ss << std::hex;
        auto result = digest();
        std::for_each(result.begin(), result.end(), [&_ss](uint32_t i) -> void {
            for (size_t _{}; _ < 4; ++_) {
                uint16_t tmp = reinterpret_cast<byte*>(&i)[is_little_endian() ? 3 - _ :  _];
                _ss << (tmp >= 0x10 ? '\0' : '0') << tmp;
            }
        });
        return _ss.str();
    }
    auto operator<<(const std::string& str) -> sha1& {
        update(str);
        return *this;
    }
    auto operator>>(std::string& str) -> void {
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
    auto __extend_64bytes_to_320bytes(size_t _offset) ->std::array<byte, 320> {
        std::array<byte, 320> result{};
        size_t i{};
        for (; i < 64; ++i) result[i] = __seq[i + _offset];
        while (i < 320) {
            auto _by = __cvt_byte4_to_uint32_t(&result[i - 3*4]);
            _by ^= __cvt_byte4_to_uint32_t(&result[i - 8*4]);
            _by ^= __cvt_byte4_to_uint32_t(&result[i - 14*4]);
            _by ^= __cvt_byte4_to_uint32_t(&result[i - 16*4]);
            _by = (_by << 1 | _by >> (32 - 1));
            auto __cvt_bytes = __cvt_uint32_t_to_big_endian_byte4(_by);
            for (size_t j{}; j < 4; ++j)
                result[i++] = __cvt_bytes[j];
        }
        return result;
    }
    auto __extend_to_big_endian_N512bits() -> void {
        uint64_t src_size_unit_bits = __seq.size() * 8;
        __seq.emplace_back('\x80');
        size_t insert_0_index = __seq.size();
        auto src_size_ = reinterpret_cast<byte*>(&src_size_unit_bits);
        for (size_t i{}; i < 8; ++i) {
            __seq.emplace_back(src_size_[is_little_endian() ? 7 - i : i]);
        }
        while (__seq.size() % 64) {
            __seq.emplace(std::next(__seq.begin(), insert_0_index), '\0');
        }
    }
    //byte[4] as a big endian unsigned int32_t
    //requires `b[i]` [with i = 0, 1, 2, 3] is accessible
    auto __cvt_byte4_to_uint32_t(byte* b) -> uint32_t {
        uint32_t result{0};
        for (size_t i{}; i < 4; ++i) {
            result += uint32_t(b[3 - i]) << i*8;
        }
        return result;
    }
    auto __cvt_uint32_t_to_big_endian_byte4(uint32_t ui32) ->std::array<byte, 4> {
        std::array<byte, 4> result{};
        for (size_t i{}; i < 4; ++i) {
            result[i] = reinterpret_cast<byte*>(&ui32)[is_little_endian() ? 3 - i : i];
        }
        return result;
    }
    std::vector<byte> __seq;
};
}
}