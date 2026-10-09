#include "game_admission.hpp"

#include <array>
#include <iostream>
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
        require(error.what() == code, "wrong admission rejection code");
        return;
    }
    throw std::runtime_error("expected admission rejection: " + std::string(code));
}

const Bytes richonline_wire{
    0,0,0,0, 0x20,0,0,0,
    0x67,0x45,0x23,0x01, 0xef,0xcd,0xab,0x89, 0x98,0xba,0xdc,0xfe,
    0x00,0xff,0x80,0x7f,0x5a,0xa5,0x13,0xc4, 0x10,0x32,0x54,0x76};

const Bytes legacy_wire{
    0,0,0,0, 0x28,0,0,0,
    0x67,0x45,0x23,0x01, 0xef,0xcd,0xab,0x89, 0x98,0xba,0xdc,0xfe,
    0x00,0xff,0x80,0x7f,0x5a,0xa5,0x13,0xc4, 0x10,0x32,0x54,0x76,
    0xe0,0xac,0x68,0x24, 0xdf,0x9b,0x57,0x13};

GameAdmission fixture_admission() {
    return {0x01234567U, 0x89abcdefU, 0xfedcba98U,
            {0x00,0xff,0x80,0x7f,0x5a,0xa5,0x13,0xc4}, 0x76543210U, {}};
}

void independent_fixtures() {
    const Transport modern{Channel::game_c2s, {}, ClientVersion::richonline};
    const auto modern_frame = decode_frame(richonline_wire, modern);
    const auto expected = fixture_admission();
    require(modern_frame.wire_type == 0 && modern_frame.payload.size() == 24,
            "Richonline fixture has type zero and 24 byte payload");
    require(decode_game_admission(modern_frame, ClientVersion::richonline) == expected,
            "Richonline independent bytes retain all common fields and absent legacy fields");
    require(encode_frame(encode_game_admission(expected, ClientVersion::richonline), modern) == richonline_wire,
            "Richonline encoder produces exactly 32 wire bytes");

    const Transport old{Channel::game_c2s, {}, ClientVersion::legacy};
    const auto old_frame = decode_frame(legacy_wire, old);
    auto old_expected = expected;
    old_expected.legacy_fields = std::array<std::uint32_t, 2>{0x2468ace0U, 0x13579bdfU};
    require(old_frame.wire_type == 0 && old_frame.payload.size() == 32,
            "legacy fixture has type zero and 32 byte payload");
    require(decode_game_admission(old_frame, ClientVersion::legacy) == old_expected,
            "legacy independent bytes retain nonzero trailing DWORDs");
    require(encode_frame(encode_game_admission(old_expected, ClientVersion::legacy), old) == legacy_wire,
            "legacy encoder produces exactly 40 wire bytes");
    rejects([&] { decode_game_admission(old_frame, ClientVersion::richonline); },
            "invalid_game_admission_length");
    rejects([&] { decode_game_admission(modern_frame, ClientVersion::legacy); },
            "invalid_game_admission_length");
}

void strict_boundaries() {
    for (std::size_t size = 0; size <= 40; ++size) {
        const Frame frame{0, Bytes(size, 0)};
        for (const auto version : {ClientVersion::legacy, ClientVersion::richonline}) {
            const auto expected_size = version == ClientVersion::legacy ? 32U : 24U;
            if (size == expected_size) {
                const auto parsed = decode_game_admission(frame, version);
                require(encode_game_admission(parsed, version).payload == frame.payload,
                        "exact version length is accepted and preserved");
            } else {
                rejects([&] { decode_game_admission(frame, version); }, "invalid_game_admission_length");
            }
        }
    }
    rejects([] { decode_game_admission({0, Bytes(512, 0)}, ClientVersion::richonline); },
            "invalid_game_admission_length");
    rejects([] { decode_game_admission({1, Bytes(24, 0)}, ClientVersion::richonline); },
            "invalid_game_admission_type");
    rejects([] { decode_game_admission({299, Bytes(32, 0)}, ClientVersion::legacy); },
            "invalid_game_admission_type");

    const auto unknown = static_cast<ClientVersion>(-1);
    rejects([&] { decode_game_admission({0, Bytes(24, 0)}, unknown); },
            "unsupported_game_admission_version");
    rejects([&] { encode_game_admission(fixture_admission(), unknown); },
            "unsupported_game_admission_version");

    const auto modern = fixture_admission();
    rejects([&] { encode_game_admission(modern, ClientVersion::legacy); },
            "missing_legacy_game_admission_fields");
    auto old = modern;
    old.legacy_fields = std::array<std::uint32_t, 2>{0, 0};
    rejects([&] { encode_game_admission(old, ClientVersion::richonline); },
            "richonline_game_admission_has_legacy_fields");
    require(decode_game_admission(encode_game_admission(old, ClientVersion::legacy), ClientVersion::legacy) == old,
            "explicit legacy zero fields remain present");
}

void bit_preserving_round_trips() {
    constexpr std::array<std::uint32_t, 5> edges{0U, 1U, 0x7fffffffU, 0x80000000U, 0xffffffffU};
    for (std::size_t index = 0; index < edges.size(); ++index) {
        auto admission = fixture_admission();
        admission.id0 = edges[index];
        admission.id1 = edges[(index + 1) % edges.size()];
        admission.id2 = edges[(index + 2) % edges.size()];
        admission.field20 = edges[(index + 3) % edges.size()];
        admission.legacy_fields = std::array<std::uint32_t, 2>{edges[(index + 4) % edges.size()], edges[index]};
        for (const auto version : {ClientVersion::legacy, ClientVersion::richonline}) {
            auto input = admission;
            if (version == ClientVersion::richonline) input.legacy_fields.reset();
            const auto encoded = encode_game_admission(input, version);
            const auto decoded = decode_game_admission(encoded, version);
            require(decoded == input, "DWORD boundary bit patterns survive the selected version");
            require(encode_game_admission(decoded, version).payload == encoded.payload,
                    "decode and reencode retain exact admission bytes");
        }
    }
    for (std::uint32_t byte = 0; byte < 256; ++byte) {
        auto admission = fixture_admission();
        admission.opaque8.fill(static_cast<std::uint8_t>(byte));
        const auto encoded = encode_game_admission(admission, ClientVersion::richonline);
        require(decode_game_admission(encoded, ClientVersion::richonline) == admission,
                "every opaque byte bit pattern survives without interpretation");
    }
}

}

int main() {
    try {
        independent_fixtures();
        strict_boundaries();
        bit_preserving_round_trips();
        std::cout << "game admission fixtures passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
