#pragma once
#include "endian.hpp"
namespace ccat {
inline namespace hash {
class base_of_sha224_and_sha256 {
public:
    using byte = unsigned char;
    base_of_sha224_and_sha256() = default;
    explicit base_of_sha224_and_sha256(const std::string& str) : __seq(str.begin(), str.end()) {}
    base_of_sha224_and_sha256(const base_of_sha224_and_sha256 &) = delete;
    base_of_sha224_and_sha256(base_of_sha224_and_sha256 &&other) : __seq(std::move(other.__seq)) {}
    auto operator=(const base_of_sha224_and_sha256 &other) = delete;
    auto operator=(base_of_sha224_and_sha256&& other) -> base_of_sha224_and_sha256& {
        if (std::addressof(other) != this) {
            __seq = std::move(other.__seq);
        }
        return *this;
    }
    virtual ~base_of_sha224_and_sha256(){};
//to be implemented
    virtual auto get_init_magic_nums() ->std::array<uint32_t, 8> = 0;
    virtual auto get_result_size() ->size_t = 0;
//
    auto digest() ->std::array<uint32_t, 8> {
        __extend_to_big_endian_N512bits();
        std::array<uint32_t, 8> magic_nums = get_init_magic_nums(), _H{};
        static std::array<uint32_t, 64> K{
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        for (size_t _{}; _ < __seq.size() / 64; ++_) {
            auto offset = _ * 64;
            auto _extent_seq_chunk = __extend_64bytes_to_256bytes(offset);
            _H = magic_nums;
#if defined(__cplusplus) && __cplusplus >= 201703L || defined(_MSVC_LANG) && _MSVC_LANG >= 201703L
            auto& [a, b, c, d, e, f, g, h] = _H;
#else
            auto &a = _H[0], &b = _H[1], &c = _H[2], &d = _H[3], &e = _H[4], &f = _H[5], &g = _H[6], &h = _H[7];
#endif
            for (size_t i{}; i < 64; ++i) {
                auto _S1 = __rrotate(e, 6) ^ __rrotate(e, 11) ^ __rrotate(e, 25);
                auto _ch = (e & f) ^ ((~e) & g);
                auto _w = __cvt_byte4_to_uint32_t(&_extent_seq_chunk[i*4]);
                auto _S0 = __rrotate(a, 2) ^ __rrotate(a, 13) ^ __rrotate(a, 22);
                auto _maj = (a & b) ^ (a & c) ^ (b & c);
                auto _Forml = h + _S1 + _ch + K[i] + _w;
                d += _Forml;
                h = _Forml + _S0 + _maj;
                auto tmp = _H[7];
                for (size_t j = 7; j > 0; --j) _H[j] = _H[j-1]; 
                _H[0] = tmp;
            }
            for (size_t j{}; j < 8; ++j) magic_nums[j] += _H[j];
        }
        return magic_nums;
    }
    auto hexdigest() ->std::string {
        std::stringstream _ss;
        _ss << std::hex;
        auto result = digest();
        std::for_each(result.begin(), std::next(result.begin(), get_result_size() / 4), [&_ss](uint32_t i) -> void {
            for (size_t _{}; _ < 4; ++_) {
                uint16_t tmp = reinterpret_cast<byte*>(&i)[is_little_endian() ? 3 - _ : _];
                _ss << (tmp >= 0x10 ? '\0' : '0') << tmp;
            }
        });
        return _ss.str();
    }
    auto update(const std::string& str) -> void {
        std::copy(str.begin(), str.end(), std::back_inserter(__seq));
    }
    auto operator<<(const std::string& str) -> base_of_sha224_and_sha256& {
        update(str);
        return *this;
    }
    auto operator>>(std::string& str) -> void {
        str = hexdigest();
        clear();
    }
    auto clear() -> void {
        __seq.clear();
    }
    auto empty() -> bool {
        return __seq.empty();
    }
protected:
    auto __extend_64bytes_to_256bytes(size_t _offset) -> std::array<byte, 256> {
        std::array<byte, 256> result{};
        size_t i{};
        for (; i < 64; ++i) result[i] = __seq[i + _offset];
        while (i < 256) {
            auto _s0 = __cvt_byte4_to_uint32_t(&result[i - 15 * 4]);
            auto _s1 = __cvt_byte4_to_uint32_t(&result[i - 2 * 4]);
            auto _s2 = __cvt_byte4_to_uint32_t(&result[i - 16 * 4]);
            auto _s3 = __cvt_byte4_to_uint32_t(&result[i - 7 * 4]);
            _s0 = __rrotate(_s0, 7) ^ __rrotate(_s0, 18) ^ (_s0 >> 3);
            _s1 = __rrotate(_s1, 17) ^ __rrotate(_s1, 19) ^ (_s1 >> 10);
            auto __cvt_bytes = __cvt_uint32_t_to_big_endian_byte4(_s0 + _s1 + _s2 + _s3);
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
            result += uint32_t(b[3 - i]) << i * 8;
        }
        return result;
    }
    auto __cvt_uint32_t_to_big_endian_byte4(uint32_t _ui32) -> std::array<byte, 4> {
        std::array<byte, 4> result{};
        for (size_t i{}; i < 4; ++i) {
            result[i] = reinterpret_cast<byte*>(&_ui32)[is_little_endian() ? 3 - i : i];
        }
        return result;
    }
    constexpr auto __rrotate(uint32_t _ui32, size_t n) ->uint32_t {
        return (_ui32 >> n) | (_ui32 << (32 - n));
    }
    std::vector<byte> __seq;  
};


class sha256 final : public base_of_sha224_and_sha256 {
public:
    constexpr static size_t result_length = 32;//unit: bytes
    auto get_init_magic_nums() -> std::array<uint32_t, 8> override {
        return {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
    }
    auto get_result_size() ->size_t override {
        return result_length;
    }
};


class sha224 final : public base_of_sha224_and_sha256 {
public:
    using byte = unsigned char;
    constexpr static size_t result_length = 28;//unit: bytes
    auto get_init_magic_nums() -> std::array<uint32_t, 8> override {
        return {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        };
    }
    auto get_result_size() ->size_t override {
        return result_length;
    }
};

}
}