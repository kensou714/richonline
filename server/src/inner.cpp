#include "codec.hpp"

#include <algorithm>
#include <bit>

namespace richnet {
namespace {
std::size_t envelope_tail_size(ClientVersion version) {
    // 新版 299 信封没有旧版的四字节尾部，不能为了共用布局而补零。
    switch (version) {
    case ClientVersion::legacy: return 4;
    case ClientVersion::richonline: return 0;
    }
    throw CodecError("invalid_client_version");
}
}
Bytes encode_inner(View plain, View filler) {
    // 长度与明文一起加 107、倒序，再与填充字节交织；这是协议变换，不是安全加密。
    if (plain.size() < 2 || plain.size() > 509)
        throw CodecError("inner_plain_length_out_of_encoder_range");
    if (filler.size() != plain.size() + 2) throw CodecError("inner_filler_length_mismatch");
    Bytes transformed;
    append_le(transformed, static_cast<std::uint32_t>(plain.size()), 2);
    transformed.insert(transformed.end(), plain.begin(), plain.end());
    for (auto& value : transformed) value = static_cast<std::uint8_t>((value + 107U) & 255U);
    std::reverse(transformed.begin(), transformed.end());
    Bytes encoded;
    encoded.reserve(transformed.size() * 2);
    for (std::size_t index = 0; index < transformed.size(); ++index) {
        encoded.push_back(filler[index]);
        encoded.push_back(transformed[index]);
    }
    return encoded;
}

Bytes decode_inner(View encoded) {
    if (encoded.size() < 8 || encoded.size() > 1024 || encoded.size() % 2 != 0)
        throw CodecError("invalid_inner_encoded_length");
    Bytes transformed;
    transformed.reserve(encoded.size() / 2);
    for (std::size_t index = encoded.size() - 1; ; index -= 2) {
        transformed.push_back(static_cast<std::uint8_t>((encoded[index] + 256U - 107U) & 255U));
        if (index == 1) break;
    }
    const auto declared = read_le(View(transformed).first(2));
    if (declared < 2 || declared != transformed.size() - 2)
        throw CodecError("inner_declared_length_mismatch");
    return Bytes(transformed.begin() + 2, transformed.end());
}

Frame encode_envelope(const Envelope299& envelope, ClientVersion version) {
    if (envelope.encoded.size() > 32767) throw CodecError("envelope_W_exceeds_signed_i16");
    const auto tail_size = envelope_tail_size(version);
    if (tail_size == 0 && envelope.tail != std::array<std::uint8_t, 4>{})
        throw CodecError("richonline_envelope_has_no_tail");
    Bytes payload;
    append_le(payload, std::bit_cast<std::uint16_t>(envelope.inner_type), 2);
    append_le(payload, static_cast<std::uint32_t>(envelope.encoded.size()), 2);
    payload.push_back(std::bit_cast<std::uint8_t>(envelope.mode));
    payload.insert(payload.end(), envelope.encoded.begin(), envelope.encoded.end());
    payload.insert(payload.end(), envelope.tail.begin(), envelope.tail.begin() + static_cast<std::ptrdiff_t>(tail_size));
    return Frame{299, std::move(payload)};
}

Envelope299 decode_envelope(const Frame& frame, ClientVersion version) {
    const auto payload = View(frame.payload);
    const auto tail_size = envelope_tail_size(version);
    if (frame.wire_type != 299 || payload.size() < 5 + tail_size) throw CodecError("invalid_envelope_header");
    const auto encoded_size = read_le(payload.subspan(2, 2));
    if (encoded_size > 32767 || payload.size() != encoded_size + 5 + tail_size)
        throw CodecError("envelope_W_or_tail_length_mismatch");
    std::array<std::uint8_t, 4> tail{};
    const auto encoded_end = payload.end() - static_cast<std::ptrdiff_t>(tail_size);
    std::copy(encoded_end, payload.end(), tail.begin());
    return Envelope299{
        std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(payload.first(2)))),
        std::bit_cast<std::int8_t>(payload[4]),
        Bytes(payload.begin() + 5, encoded_end), tail};
}
}
