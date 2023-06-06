#pragma once
#include "endian.hpp"

CCAT_MOD_EXPORT namespace ccat {
namespace hashlib {

class base_of_sha384_and_sha512 {
public:
    using byte = unsigned char;
    base_of_sha384_and_sha512() = default;
    base_of_sha384_and_sha512(const base_of_sha384_and_sha512&) = delete;
    base_of_sha384_and_sha512(base_of_sha384_and_sha512&& other) noexcept : __seq(std::move(other.__seq)) {}
    auto operator= (const base_of_sha384_and_sha512&) ->base_of_sha384_and_sha512& = delete;
    auto operator= (base_of_sha384_and_sha512&& other) noexcept ->base_of_sha384_and_sha512& {
        if (std::addressof(other) != this) {
            __seq = std::move(other.__seq);
        }
        return *this;
    }
    virtual ~base_of_sha384_and_sha512() = default;
//to be implemented:
    virtual auto get_init_magic_nums() -> std::array<uint64_t, 8> = 0;
    virtual auto get_result_size() ->size_t = 0;
//
    auto hexdigest() ->std::string {
        std::stringstream _ss;
        _ss << std::hex;
        auto result = digest();
        std::for_each(result.begin(), std::next(result.begin(), get_result_size() / 8), [&_ss](uint64_t i) -> void {
            for (size_t _{}; _ < 8; ++_) {
                uint16_t tmp = reinterpret_cast<byte*>(&i)[is_little_endian() ? 7 - _ : _];
                if (tmp < 0x10) _ss << '0';
                _ss << tmp;
            }
        });
        return _ss.str();
    }
    auto digest() -> std::array<uint64_t, 8> {
        __extend_to_big_endian_N1024bits();
        std::array<uint64_t, 8> magic_nums = get_init_magic_nums(), _H{};
        static std::array<uint64_t, 80> K{
                0x428a2f98d728ae22u, 0x7137449123ef65cdu, 0xb5c0fbcfec4d3b2fu, 0xe9b5dba58189dbbcu,
                0x3956c25bf348b538u, 0x59f111f1b605d019u, 0x923f82a4af194f9bu, 0xab1c5ed5da6d8118u,
                0xd807aa98a3030242u, 0x12835b0145706fbeu, 0x243185be4ee4b28cu, 0x550c7dc3d5ffb4e2u,
                0x72be5d74f27b896fu, 0x80deb1fe3b1696b1u, 0x9bdc06a725c71235u, 0xc19bf174cf692694u,
                0xe49b69c19ef14ad2u, 0xefbe4786384f25e3u, 0x0fc19dc68b8cd5b5u, 0x240ca1cc77ac9c65u,
                0x2de92c6f592b0275u, 0x4a7484aa6ea6e483u, 0x5cb0a9dcbd41fbd4u, 0x76f988da831153b5u,
                0x983e5152ee66dfabu, 0xa831c66d2db43210u, 0xb00327c898fb213fu, 0xbf597fc7beef0ee4u,
                0xc6e00bf33da88fc2u, 0xd5a79147930aa725u, 0x06ca6351e003826fu, 0x142929670a0e6e70u,
                0x27b70a8546d22ffcu, 0x2e1b21385c26c926u, 0x4d2c6dfc5ac42aedu, 0x53380d139d95b3dfu,
                0x650a73548baf63deu, 0x766a0abb3c77b2a8u, 0x81c2c92e47edaee6u, 0x92722c851482353bu,
                0xa2bfe8a14cf10364u, 0xa81a664bbc423001u, 0xc24b8b70d0f89791u, 0xc76c51a30654be30u,
                0xd192e819d6ef5218u, 0xd69906245565a910u, 0xf40e35855771202au, 0x106aa07032bbd1b8u,
                0x19a4c116b8d2d0c8u, 0x1e376c085141ab53u, 0x2748774cdf8eeb99u, 0x34b0bcb5e19b48a8u,
                0x391c0cb3c5c95a63u, 0x4ed8aa4ae3418acbu, 0x5b9cca4f7763e373u, 0x682e6ff3d6b2b8a3u,
                0x748f82ee5defb2fcu, 0x78a5636f43172f60u, 0x84c87814a1f0ab72u, 0x8cc702081a6439ecu,
                0x90befffa23631e28u, 0xa4506cebde82bde9u, 0xbef9a3f7b2c67915u, 0xc67178f2e372532bu,
                0xca273eceea26619cu, 0xd186b8c721c0c207u, 0xeada7dd6cde0eb1eu, 0xf57d4f7fee6ed178u,
                0x06f067aa72176fbau, 0x0a637dc5a2c898a6u, 0x113f9804bef90daeu, 0x1b710b35131c471bu,
                0x28db77f523047d84u, 0x32caab7b40c72493u, 0x3c9ebe0a15c9bebcu, 0x431d67c49c100d4cu,
                0x4cc5d4becb3e42b6u, 0x597f299cfc657e2au, 0x5fcb6fab3ad6faecu, 0x6c44198c4a475817u
        };
        for (size_t _{}; _ < __seq.size() / 128; ++_) {
            auto offset = _ * 128;
            auto _extent_seq_chunk = __extend_128bytes_to_640bytes(offset);
            _H = magic_nums;
#if defined(__cplusplus) && __cplusplus >= 201703L || defined(_MSVC_LANG) && _MSVC_LANG >= 201703L
            auto& [a, b, c, d, e, f, g, h] = _H;
#else
            auto &a = _H[0], &b = _H[1], &c = _H[2], &d = _H[3], &e = _H[4], &f = _H[5], &g = _H[6], &h = _H[7];
#endif
            for (size_t i{}; i < 80; ++i) {
                auto _S1 = __rrotate(e, 14) ^ __rrotate(e, 18) ^ __rrotate(e, 41);
                auto _ch = (e & f) ^ ((~e) & g);
                auto _w = __cvt_byte8_to_uint64_t(&_extent_seq_chunk[i * 8]);
                auto _S0 = __rrotate(a, 28) ^ __rrotate(a, 34) ^ __rrotate(a, 39);
                auto _maj = (a & b) ^ (a & c) ^ (b & c);
                auto _Forml = h + _S1 + _ch + K[i] + _w;
                d += _Forml;
                h = _Forml + _S0 + _maj;
                auto tmp = _H[7];
                for (size_t j = 7; j > 0; --j) _H[j] = _H[j - 1];
                _H[0] = tmp;
            }
            for (size_t j{}; j < 8; ++j) magic_nums[j] += _H[j];
        }
        return magic_nums;
    }
    auto update(const std::string& str) ->base_of_sha384_and_sha512& {
        std::copy(str.begin(), str.end(), std::back_inserter(__seq));
        return *this;
    }
    auto operator>>(std::string& str) -> void {
        str = hexdigest();
        clear();
    }
    auto operator<<(const std::string& str) ->base_of_sha384_and_sha512& {
        update(str);
        return *this;
    }
    auto clear() -> void {
        __seq.clear();
    }
    auto empty() -> bool {
        return __seq.empty();
    }
protected:
    auto __extend_128bytes_to_640bytes(size_t _offset) -> std::array<byte, 640> {
        std::array<byte, 640> result{};
        size_t i{};
        for (; i < 128; ++i) result[i] = __seq[i + _offset];
        while (i < 640) {
            auto _s0 = __cvt_byte8_to_uint64_t(&result[i - 15 * 8]);
            auto _s1 = __cvt_byte8_to_uint64_t(&result[i - 2 * 8]);
            auto _s2 = __cvt_byte8_to_uint64_t(&result[i - 16 * 8]);
            auto _s3 = __cvt_byte8_to_uint64_t(&result[i - 7 * 8]);
            _s0 = __rrotate(_s0, 1) ^ __rrotate(_s0, 8) ^ (_s0 >> 7);
            _s1 = __rrotate(_s1, 19) ^ __rrotate(_s1, 61) ^ (_s1 >> 6);
            auto __cvt_bytes = __cvt_uint64_t_to_big_endian_byte8(_s0 + _s1 + _s2 + _s3);
            for (size_t j{}; j < 8; ++j)
                result[i++] = __cvt_bytes[j];
        }
        return result;
    }
    auto __extend_to_big_endian_N1024bits() -> void {
        uint64_t src_size_unit_bits = __seq.size() * 8;
        __seq.emplace_back('\x80');
        size_t insert_0_index = __seq.size();
        auto src_size_ = reinterpret_cast<byte*>(&src_size_unit_bits);
        for (size_t i{}; i < 16; ++i) {
            __seq.emplace_back(i < 8 ? '\0' : src_size_[is_little_endian() ? 7 - i + 8 : i - 8]);
        }
        while (__seq.size() % 128) {
            __seq.emplace(std::next(__seq.begin(), insert_0_index), '\0');
        }
    }
    auto __cvt_byte8_to_uint64_t(byte* b) -> uint64_t {
        uint64_t result{0};
        for (size_t i{}; i < 8; ++i) {
            result += uint64_t(b[7 - i]) << i * 8;
        }
        return result;
    }
    auto __cvt_uint64_t_to_big_endian_byte8(uint64_t _ui64) -> std::array<byte, 8> {
        std::array<byte, 8> result{};
        for (size_t i{}; i < 8; ++i) {
            result[i] = reinterpret_cast<byte*>(&_ui64)[is_little_endian() ? 7 - i : i];
        }
        return result;
    }
    constexpr auto __rrotate(uint64_t _ui64, size_t n) -> uint64_t {
        return (_ui64 >> n) | (_ui64 << (64 - n));
    }
    std::vector<byte> __seq;
};



class sha512 final : public base_of_sha384_and_sha512 {
public:
    using base_of_sha384_and_sha512::base_of_sha384_and_sha512;
    constexpr static size_t result_length = 64;//unit: bytes
    auto get_init_magic_nums() -> std::array<uint64_t, 8> override {
        return {
            0x6a09e667f3bcc908u, 0xbb67ae8584caa73bu, 
            0x3c6ef372fe94f82bu, 0xa54ff53a5f1d36f1u,
            0x510e527fade682d1u, 0x9b05688c2b3e6c1fu,
            0x1f83d9abfb41bd6bu, 0x5be0cd19137e2179u
        };
    }
    auto get_result_size() ->size_t override {
        return result_length;
    }
};


class sha384 final : public base_of_sha384_and_sha512 {
public:
    using base_of_sha384_and_sha512::base_of_sha384_and_sha512;
    constexpr static size_t result_length = 48;//unit: bytes
    auto get_init_magic_nums() -> std::array<uint64_t, 8> override {
        return {
            0xcbbb9d5dc1059ed8u, 0x629a292a367cd507u, 
            0x9159015a3070dd17u, 0x152fecd8f70e5939u, 
            0x67332667ffc00b31u, 0x8eb44a8768581511u,
            0xdb0c2e0d64f98fa7u, 0x47b5481dbefa4fa4u
        };
    }
    auto get_result_size() ->size_t override {
        return result_length;
    }
};
}
}
