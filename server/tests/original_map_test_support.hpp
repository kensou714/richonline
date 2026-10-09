#pragma once

#include "original_map.hpp"
#include "../vendor/lzokay/lzokay.hpp"
#include <algorithm>
#include <bit>
#include <fstream>
#include <nlohmann/json.hpp>

namespace map_test {
using namespace richnet;
inline void check(bool condition, std::string_view reason) {
    if (!condition) throw std::runtime_error(std::string(reason));
}
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) {
        check(error.what() == code, std::string("expected ") + std::string(code) + ", got " + error.what());
        return;
    }
    throw std::runtime_error("expected rejection: " + std::string(code));
}
inline void put(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    check(offset <= bytes.size() && bytes.size() - offset >= 4, "test fixture write out of range");
    for (unsigned i = 0; i < 4; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8U));
}
inline std::int32_t integer(View bytes, std::size_t offset) {
    return std::bit_cast<std::int32_t>(read_le(bytes.subspan(offset, 4)));
}
inline Bytes from_hex(std::string_view value) {
    check(value.size() % 2 == 0, "oracle odd hex length");
    const auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        throw std::runtime_error("oracle invalid hex digit");
    };
    Bytes bytes;
    for (std::size_t i = 0; i < value.size(); i += 2)
        bytes.push_back(static_cast<std::uint8_t>((nibble(value[i]) << 4U) | nibble(value[i+1])));
    return bytes;
}
inline OriginalEmp fixture() {
    constexpr std::size_t terrain = 20, types = terrain + 4 * 64 + 4;
    constexpr std::size_t properties = types + 4 * 4, tail = properties + 4 * 88;
    OriginalEmp emp{3, 2, 2, {}, Bytes(23432, 0xa5), Bytes(tail + 172 + 3, 0), terrain, types, properties, tail};
    for (std::size_t i = 0; i < emp.signature.size(); ++i) emp.signature[i] = static_cast<std::uint8_t>(0x90 + i);
    std::copy(emp.signature.begin(), emp.signature.end(), emp.header.begin());
    put(emp.header, 16, 3); put(emp.header, 23304, 2); put(emp.header, 23308, 2);
    put(emp.payload, 0, 1); put(emp.payload, 4, 1);
    put(emp.payload, 8, 1); put(emp.payload, 12, 1); put(emp.payload, 16, 0x12345678);
    for (std::size_t i = 0; i < 4; ++i) {
        put(emp.payload, terrain + i * 64, static_cast<std::uint32_t>(10 + i));
        put(emp.payload, terrain + i * 64 + 56, i < 2 ? static_cast<std::uint32_t>(i) : 0xffffffff);
        put(emp.payload, terrain + i * 64 + 60, i < 2 ? 0 : 0xffffffff);
        put(emp.payload, types + i * 4, static_cast<std::uint32_t>(20 + i));
        put(emp.payload, properties + i * 88, i == 0 ? 12 : 11);
        put(emp.payload, properties + i * 88 + 12, i == 0 ? 0 : 1);
        put(emp.payload, properties + i * 88 + 16, static_cast<std::uint32_t>(i));
        put(emp.payload, properties + i * 88 + 56, static_cast<std::uint32_t>(50 + i));
    }
    put(emp.payload, tail + 104, 1200); put(emp.payload, tail + 108, 2300);
    put(emp.payload, tail + 112, 3400); put(emp.payload, tail + 116, 4);
    put(emp.payload, tail + 120, 2); put(emp.payload, tail + 124, 0xdeadbeef); put(emp.payload, tail + 128, 0x89abcdef);
    put(emp.payload, tail + 132, 2); put(emp.payload, tail + 136, 3); put(emp.payload, tail + 140, 4);
    put(emp.payload, tail + 144, 27); put(emp.payload, tail + 148, 9);
    put(emp.payload, tail + 152, 2); put(emp.payload, tail + 156, 27); put(emp.payload, tail + 160, 3);
    put(emp.payload, tail + 164, 1); put(emp.payload, tail + 168, 27);
    emp.payload[tail + 172] = 0x11; emp.payload[tail + 173] = 0x22; emp.payload[tail + 174] = 0x33;
    return emp;
}
inline Bytes encode_fixture(const OriginalEmp& emp) {
    Bytes compressed(lzokay::compress_worst_size(emp.payload.size()));
    std::size_t compressed_size = 0;
    check(lzokay::compress(emp.payload.data(), emp.payload.size(), compressed.data(), compressed.size(), compressed_size)
          == lzokay::EResult::Success, "fixture LZO compression");
    compressed.resize(compressed_size);
    Bytes block{0x3d};
    append_le(block, static_cast<std::uint32_t>(emp.payload.size()), 4);
    append_le(block, static_cast<std::uint32_t>(compressed.size()), 4);
    block.insert(block.end(), compressed.begin(), compressed.end());
    for (std::size_t i = 1; i < block.size(); ++i) block[i] = static_cast<std::uint8_t>(block[i] + block[0]);
    auto file = emp.header;
    file.insert(file.end(), block.begin(), block.end());
    return file;
}
inline nlohmann::json oracle(const std::filesystem::path& path) {
    std::ifstream input(path.c_str(), std::ios::binary);
    check(static_cast<bool>(input), "missing existing map oracle: " + path.filename().string());
    return nlohmann::json::parse(input);
}
}
