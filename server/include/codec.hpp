#pragma once

// 传输编解码：区分大厅/游戏、收发方向以及旧版/新版客户端，负责帧与 299 包装。

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace richnet {
using Bytes = std::vector<std::uint8_t>;
// 只读借用视图，不延长底层缓冲区的生命周期。
using View = std::span<const std::uint8_t>;
inline constexpr std::uint32_t max_frame_total = 1U << 20U;
inline constexpr std::array<std::uint8_t, 4> magic{0x5f, 0xd8, 0xa1, 0x10};

class CodecError : public std::runtime_error {
public:
    explicit CodecError(const std::string& code) : std::runtime_error(code) {}
};

enum class Channel { lobby_c2s, lobby_s2c, game_c2s, game_s2c };
enum class ClientVersion { legacy, richonline };
struct Transport {
    Channel channel;
    std::optional<std::int32_t> key;
    ClientVersion version = ClientVersion::legacy;
};
struct Frame {
    std::uint32_t wire_type;
    Bytes payload;
};
struct Envelope299 {
    std::int16_t inner_type;
    std::int8_t mode;
    Bytes encoded;
    // 新版线协议没有此尾部；全零仅表示内部的“尾部不存在”。
    std::array<std::uint8_t, 4> tail{};
};

std::uint32_t read_le(View data);
void append_le(Bytes& data, std::uint32_t value, std::size_t width);
Bytes encode_frame(const Frame& frame, Transport transport);
Frame decode_frame(View packet, Transport transport);
Bytes encode_inner(View plain, View filler);
Bytes decode_inner(View encoded);
Frame encode_envelope(const Envelope299& envelope, ClientVersion version = ClientVersion::legacy);
Envelope299 decode_envelope(const Frame& frame, ClientVersion version = ClientVersion::legacy);
// 新版 0x8DFFF0：IMUL 截取低 32 位，再用有符号 IDIV 求余；指数和模数须为正。
std::int32_t modpow_signed32(std::int32_t base, std::int32_t exponent, std::int32_t modulus);

class StreamDecoder final {
public:
    explicit StreamDecoder(Transport transport) : transport_(transport) {}
    // 可输入半包或粘包；只返回完整帧，未完成部分保存在实例中。
    std::vector<Frame> feed(View chunk);
    // 连接结束时检查残留半包；截断流以 CodecError 报错。
    void finish() const;
private:
    Transport transport_;
    Bytes pending_;
};
}
