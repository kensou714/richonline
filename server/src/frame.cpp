#include "codec.hpp"

#include <algorithm>

namespace richnet {
namespace {
std::size_t prefix_size(Channel channel) {
    switch (channel) {
    case Channel::lobby_c2s: return magic.size();
    case Channel::lobby_s2c:
    case Channel::game_c2s:
    case Channel::game_s2c: return 0;
    }
    throw CodecError("invalid_channel");
}

Bytes transformed(const Frame& frame, Transport transport) {
    Bytes output = frame.payload;
    if (!transport.key) return output;
    switch (transport.channel) {
    case Channel::game_c2s:
    case Channel::game_s2c: throw CodecError("game_transport_has_no_lobby_key");
    case Channel::lobby_c2s:
    case Channel::lobby_s2c: break;
    }
    bool reverse = false;
    switch (transport.version) {
    case ClientVersion::legacy:
        if (frame.wire_type == 579 || frame.wire_type == 759)
            throw CodecError("handshake_payload_must_remain_plain");
        if (*transport.key < 0) throw CodecError("key_out_of_nonnegative_i32_subset");
        reverse = *transport.key % 2 != 0;
        break;
    case ClientVersion::richonline:
        if (transport.channel == Channel::lobby_c2s && frame.wire_type == 759)
            throw CodecError("handshake_payload_must_remain_plain");
        // 新版两个方向的有符号余数判断不同：8DF990 判断非零，8DFAC0 判断等于 1。
        reverse = transport.channel == Channel::lobby_c2s
            ? *transport.key % 2 != 0 : *transport.key % 2 == 1;
        break;
    }
    const auto byte_key = static_cast<std::uint8_t>(*transport.key & 255);
    for (auto& value : output) value ^= byte_key;
    if (reverse) std::reverse(output.begin(), output.end());
    return output;
}

std::uint32_t parse_total(View header, std::size_t prefix) {
    if (prefix != 0 && !std::equal(magic.begin(), magic.end(), header.begin()))
        throw CodecError("invalid_lobby_magic");
    const auto total = read_le(header.subspan(prefix + 4, 4));
    if (total < 8 || total > max_frame_total) throw CodecError("invalid_frame_total");
    return total;
}
}

std::uint32_t read_le(View data) {
    if (data.size() > 4) throw CodecError("integer_width_exceeds_u32");
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < data.size(); ++index)
        value |= static_cast<std::uint32_t>(data[index]) << (8U * index);
    return value;
}

void append_le(Bytes& data, std::uint32_t value, std::size_t width) {
    if (width > 4) throw CodecError("integer_width_exceeds_u32");
    for (std::size_t index = 0; index < width; ++index)
        data.push_back(static_cast<std::uint8_t>((value >> (8U * index)) & 255U));
}

Bytes encode_frame(const Frame& frame, Transport transport) {
    if (frame.payload.size() > max_frame_total - 8)
        throw CodecError("frame_exceeds_local_limit");
    const auto payload = transformed(frame, transport);
    Bytes packet;
    packet.reserve(prefix_size(transport.channel) + 8 + payload.size());
    if (prefix_size(transport.channel) != 0) packet.insert(packet.end(), magic.begin(), magic.end());
    append_le(packet, frame.wire_type, 4);
    // total 包含 8 字节帧头，不包含大厅上行独有的 magic 前缀。
    append_le(packet, static_cast<std::uint32_t>(payload.size() + 8), 4);
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

Frame decode_frame(View packet, Transport transport) {
    const auto prefix = prefix_size(transport.channel);
    if (packet.size() < prefix + 8) throw CodecError("truncated_frame_header");
    const auto total = parse_total(packet, prefix);
    if (packet.size() != prefix + total) throw CodecError("frame_total_mismatch");
    Frame frame{read_le(packet.subspan(prefix, 4)), Bytes(packet.begin() + static_cast<std::ptrdiff_t>(prefix + 8), packet.end())};
    frame.payload = transformed(frame, transport);
    return frame;
}

std::vector<Frame> StreamDecoder::feed(View chunk) {
    // 先凑齐帧头再取声明长度；一次 TCP 读取可能仅含半包，也可能包含多个包。
    std::vector<Frame> frames;
    const auto prefix = prefix_size(transport_.channel);
    const auto header_size = prefix + 8;
    while (!chunk.empty()) {
        const auto target_size = pending_.size() < header_size
            ? header_size : prefix + parse_total(pending_, prefix);
        const auto take = std::min(target_size - pending_.size(), chunk.size());
        pending_.insert(pending_.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(take));
        chunk = chunk.subspan(take);
        if (pending_.size() >= header_size) {
            const auto complete_size = prefix + parse_total(pending_, prefix);
            if (pending_.size() == complete_size) {
                frames.push_back(decode_frame(pending_, transport_));
                pending_.clear();
            }
        }
    }
    return frames;
}

void StreamDecoder::finish() const {
    if (!pending_.empty()) throw CodecError("truncated_stream");
}
}
