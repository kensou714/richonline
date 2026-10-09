#include "codec.hpp"

#include <iostream>
#include <limits>
#include <string_view>

namespace {
using namespace richnet;

void require(bool condition, std::string_view name) {
    if (!condition) throw std::runtime_error(std::string(name));
}

template<class Action>
void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) {
        require(error.what() == code, "wrong rejection code");
        return;
    }
    throw std::runtime_error("expected codec rejection: " + std::string(code));
}

void frame_fixtures() {
    const Frame plain{58, {0x10, 0x20, 0x30}};
    const Transport client{Channel::lobby_c2s, 3, ClientVersion::richonline};
    const Bytes expected{0x5f,0xd8,0xa1,0x10, 58,0,0,0, 11,0,0,0, 0x33,0x23,0x13};
    require(encode_frame(plain, client) == expected, "C2S fixed header and encrypted bytes");
    require(decode_frame(expected, client).payload == plain.payload, "C2S independent fixture decode");
    const Transport server{Channel::lobby_s2c, 2, ClientVersion::richonline};
    const Bytes inbound{58,0,0,0, 11,0,0,0, 0x12,0x22,0x32};
    require(encode_frame(plain, server) == inbound, "S2C total includes eight byte header");
    require(decode_frame(inbound, server).payload == plain.payload, "S2C independent fixture decode");
    const Bytes game{0x2b,1,0,0, 11,0,0,0, 0x10,0x20,0x30};
    require(encode_frame({299, plain.payload}, {Channel::game_c2s, {}}) == game, "game has no magic");
}

void stream_fragments() {
    const Bytes first{0x5f,0xd8,0xa1,0x10, 16,0,0,0, 12,0,0,0, 0x78,0x56,0x34,0x12};
    const Bytes second{0x5f,0xd8,0xa1,0x10, 5,0,0,0, 8,0,0,0};
    Bytes joined = first;
    joined.insert(joined.end(), second.begin(), second.end());
    const Transport transport{Channel::lobby_c2s, {}, ClientVersion::richonline};
    for (std::size_t split = 0; split <= joined.size(); ++split) {
        StreamDecoder decoder(transport);
        auto frames = decoder.feed(View(joined).first(split));
        auto remainder = decoder.feed(View(joined).subspan(split));
        frames.insert(frames.end(), remainder.begin(), remainder.end());
        decoder.finish();
        require(frames.size() == 2 && frames[0].wire_type == 16 && frames[1].wire_type == 5,
                "every stream split preserves both messages");
        require(frames[0].payload == Bytes({0x78,0x56,0x34,0x12}) && frames[1].payload.empty(),
                "fragmented fixed payloads");
    }
    StreamDecoder partial(transport);
    require(partial.feed(View(first).first(15)).empty(), "incomplete stream yields nothing");
    rejects([&] { partial.finish(); }, "truncated_stream");
    StreamDecoder bytes(transport);
    std::size_t count = 0;
    for (const auto byte : joined) count += bytes.feed(View(&byte, 1)).size();
    bytes.finish();
    require(count == 2, "single byte fragmentation");
}

void envelope_versions() {
    const Envelope299 envelope{0x1234, -1, {0xaa,0xbb}, {}};
    const Frame modern{299, {0x34,0x12, 2,0, 0xff, 0xaa,0xbb}};
    const Frame legacy{299, {0x34,0x12, 2,0, 0xff, 0xaa,0xbb, 0,0,0,0}};
    require(encode_envelope(envelope, ClientVersion::richonline).payload == modern.payload,
            "richonline envelope has exactly five byte header and no tail");
    require(encode_envelope(envelope).payload == legacy.payload, "default envelope stays legacy");
    const auto parsed = decode_envelope(modern, ClientVersion::richonline);
    require(parsed.inner_type == 0x1234 && parsed.mode == -1 && parsed.encoded == envelope.encoded
            && parsed.tail == std::array<std::uint8_t,4>{}, "richonline decode has internal absent-tail representation");
    require(decode_envelope(legacy).encoded == envelope.encoded, "legacy decode compatibility");
    rejects([&] { decode_envelope(legacy, ClientVersion::richonline); }, "envelope_W_or_tail_length_mismatch");
    rejects([&] { decode_envelope(modern); }, "invalid_envelope_header");
    auto with_tail = envelope;
    with_tail.tail = {1,2,3,4};
    rejects([&] { encode_envelope(with_tail, ClientVersion::richonline); }, "richonline_envelope_has_no_tail");
    require(decode_envelope(encode_envelope(with_tail)).tail == with_tail.tail, "legacy tail preserved");
    const Bytes wire{0x2b,1,0,0, 15,0,0,0, 0x34,0x12,2,0,0xff,0xaa,0xbb};
    require(encode_frame(modern, {Channel::game_s2c, {}, ClientVersion::richonline}) == wire,
            "richonline 299 independent full wire fixture");
}

void signed_keys() {
    const Frame plain{16, {0,1,2}};
    struct Case { std::int32_t key; Bytes c2s; Bytes s2c; };
    const Case cases[]{
        {-1, {0xfd,0xfe,0xff}, {0xff,0xfe,0xfd}},
        {-2, {0xfe,0xff,0xfc}, {0xfe,0xff,0xfc}},
        {std::numeric_limits<std::int32_t>::min(), {0,1,2}, {0,1,2}},
        {std::numeric_limits<std::int32_t>::max(), {0xfd,0xfe,0xff}, {0xfd,0xfe,0xff}}
    };
    for (const auto& item : cases) {
        for (const auto channel : {Channel::lobby_c2s, Channel::lobby_s2c}) {
            const Transport transport{channel, item.key, ClientVersion::richonline};
            const auto wire = encode_frame(plain, transport);
            const auto header = channel == Channel::lobby_c2s ? 12 : 8;
            const Bytes payload(wire.begin() + header, wire.end());
            require(payload == (channel == Channel::lobby_c2s ? item.c2s : item.s2c), "signed key wire fixture");
            require(decode_frame(wire, transport).payload == plain.payload, "signed key codec inverse");
        }
    }
    rejects([&] { encode_frame(plain, {Channel::lobby_c2s, -1}); }, "key_out_of_nonnegative_i32_subset");
}

void handshake_boundaries() {
    require(modpow_signed32(5, 3, 23) == 10, "small modular power");
    require(modpow_signed32(50000, 2, 100000) == -67296, "imul low32 then signed remainder fixture");
    require(modpow_signed32(std::numeric_limits<std::int32_t>::min(), 1, 2147483647) == -1,
            "signed minimum base fixture");
    require(modpow_signed32(46341, 2, 2147483647) == -2147479015, "square signed overflow fixture");
    require(modpow_signed32(5, 1, 1) == 0, "positive modulus one");
    rejects([] { modpow_signed32(2, 1, 0); }, "modulus_must_be_positive");
    rejects([] { modpow_signed32(std::numeric_limits<std::int32_t>::min(), 1, -1); }, "modulus_must_be_positive");
    rejects([] { modpow_signed32(2, 0, 7); }, "exponent_must_be_positive");
    rejects([] { modpow_signed32(2, -1, 7); }, "exponent_must_be_positive");
    const Frame candidate{579, {1}};
    require(encode_frame(candidate, {Channel::lobby_s2c, 2, ClientVersion::richonline}).back() == 3,
            "579 is not a verified richonline handshake constant");
    rejects([&] { encode_frame(candidate, {Channel::lobby_s2c, 2}); }, "handshake_payload_must_remain_plain");
    rejects([] { encode_frame({759, {1,0,0,0}}, {Channel::lobby_c2s, 2, ClientVersion::richonline}); },
            "handshake_payload_must_remain_plain");
    const Bytes reply{0x5f,0xd8,0xa1,0x10, 0xf7,2,0,0, 12,0,0,0, 10,0,0,0};
    require(encode_frame({759, {10,0,0,0}}, {Channel::lobby_c2s, {}, ClientVersion::richonline}) == reply,
            "759 plaintext fixed reply");
}

void inner_fixture() {
    const Bytes encoded{0,0x7d, 1,0x9f, 2,0x6b, 3,0x6d};
    require(decode_inner(encoded) == Bytes({0x34,0x12}), "independent inner inverse fixture");
    require(encode_inner(Bytes{0x34,0x12}, Bytes{0,1,2,3}) == encoded, "independent inner encode fixture");
}

void malformed_frames() {
    const Transport client{Channel::lobby_c2s, {}, ClientVersion::richonline};
    const Bytes bad_magic{0,0,0,0, 5,0,0,0, 8,0,0,0};
    rejects([&] { decode_frame(bad_magic, client); }, "invalid_lobby_magic");
    const Bytes short_total{5,0,0,0, 7,0,0,0};
    rejects([&] { decode_frame(short_total, {Channel::lobby_s2c, {}}); }, "invalid_frame_total");
    const Bytes oversized{5,0,0,0, 1,0,0x10,0};
    rejects([&] { decode_frame(oversized, {Channel::lobby_s2c, {}}); }, "invalid_frame_total");
    const Bytes truncated{5,0,0,0, 9,0,0,0};
    rejects([&] { decode_frame(truncated, {Channel::lobby_s2c, {}}); }, "frame_total_mismatch");
    rejects([] { encode_frame({1, {}}, {Channel::game_c2s, 1, ClientVersion::richonline}); },
            "game_transport_has_no_lobby_key");
}
}

int main() {
    try {
        frame_fixtures(); stream_fragments(); envelope_versions(); signed_keys(); handshake_boundaries(); inner_fixture(); malformed_frames();
        std::cout << "codec regression fixtures passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
