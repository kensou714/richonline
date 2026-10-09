#include "original_game_redirect.hpp"
#include "pending_game_admissions.hpp"

#include <iostream>
#include <string_view>

namespace {
using namespace richnet;

void check(bool condition, std::string_view reason) {
    if (!condition) throw std::runtime_error(std::string(reason));
}

template<class Action>
void rejects(Action action, std::string_view code) {
    try { action(); }
    catch (const CodecError& error) {
        check(error.what() == code, "unexpected rejection code");
        return;
    }
    throw std::runtime_error("expected rejection: " + std::string(code));
}

const OriginalGameRedirect redirect{{{192, 0, 2, 231}, 18602}, 0x12345678U, 0x89abcdefU, 0xfedcba98U};

void redirect_matches_independent_packed_fixture() {
    const auto frame = encode_original_game_redirect(redirect);
    const Bytes payload{192,0,2,231, 0xaa,0x48, 0x78,0x56,0x34,0x12,
                        0xef,0xcd,0xab,0x89, 0x98,0xba,0xdc,0xfe};
    check(frame.wire_type == 22 && frame.payload == payload, "packed redirect field offsets differ");
    const Transport lobby{Channel::lobby_s2c, {}, ClientVersion::legacy};
    const auto decoded = decode_frame(encode_frame(frame, lobby), lobby);
    check(decoded.wire_type == 22 && decoded.payload == payload, "original lobby redirect roundtrip failed");
}

void original_admission_matches_independent_client_echo() {
    const auto admission = original_expected_admission({0x1234, 0x2345, 0x3456}, redirect);
    const Bytes wire{0,0,0,0, 40,0,0,0,
                     0x34,0x12,0,0, 0x45,0x23,0,0, 0x56,0x34,0,0,
                     0xef,0xcd,0xab,0x89, 0x98,0xba,0xdc,0xfe, 0x78,0x56,0x34,0x12,
                     0,0,0,0, 0,0,0,0};
    const Transport game{Channel::game_c2s, {}, ClientVersion::legacy};
    const auto encoded = encode_game_admission(admission, ClientVersion::legacy);
    check(encode_frame(encoded, game) == wire, "client room/game/user/B/C/A/zero/zero echo differs");
    check(decode_game_admission(decode_frame(wire, game), ClientVersion::legacy) == admission,
          "independent client echo did not decode to original admission");
    rejects([&] { encode_game_admission(admission, ClientVersion::richonline); },
            "richonline_game_admission_has_legacy_fields");
    rejects([&] { decode_game_admission(encoded, ClientVersion::richonline); },
            "invalid_game_admission_length");
}

void admission_is_bound_to_full_original_descriptor() {
    const auto expected = original_expected_admission({2, 3, 4}, redirect);
    const auto now = AdmissionClock::now();
    PendingGameAdmissions registry;
    registry.prepare({17, ClientVersion::legacy, expected, now + std::chrono::seconds(30)}, now);
    check(!registry.consume(ClientVersion::richonline, expected, now), "cross version admission accepted");
    for (unsigned index = 0; index != 8; ++index) {
        auto wrong = expected;
        switch (index) {
        case 0: ++wrong.id0; break;
        case 1: ++wrong.id1; break;
        case 2: ++wrong.id2; break;
        case 3: ++wrong.opaque8[0]; break;
        case 4: ++wrong.opaque8[4]; break;
        case 5: ++wrong.field20; break;
        case 6: ++(*wrong.legacy_fields)[0]; break;
        case 7: ++(*wrong.legacy_fields)[1]; break;
        }
        check(!registry.consume(ClientVersion::legacy, wrong, now), "altered original descriptor accepted");
    }
    check(registry.consume(ClientVersion::legacy, expected, now) == 17, "valid original ticket not consumed");
    check(!registry.consume(ClientVersion::legacy, expected, now), "original ticket replay accepted");
}

void redirect_boundaries() {
    auto invalid = redirect;
    invalid.endpoint.port = 0;
    rejects([&] { encode_original_game_redirect(invalid); }, "original_game_redirect_port_invalid");
    rejects([&] { original_expected_admission({0,0,0}, invalid); }, "original_game_redirect_port_invalid");
    rejects([&] { original_redirect_with_random_tokens(invalid.endpoint); }, "original_game_redirect_port_invalid");
    invalid = redirect;
    invalid.token_a = 0x80000000U;
    rejects([&] { encode_original_game_redirect(invalid); }, "original_game_redirect_token_a_out_of_range");
    rejects([&] { original_expected_admission({0,0,0}, invalid); }, "original_game_redirect_token_a_out_of_range");
    invalid.token_a = 0x7fffffffU;
    check(original_expected_admission({0,0,0}, invalid).field20 == 0x7fffffffU, "maximum token A changed");
    for (const auto identity : {OriginalAdmissionIdentity{0,0,32768}, OriginalAdmissionIdentity{0,0,0xffffffffU}})
        rejects([&] { original_expected_admission(identity, redirect); }, "original_game_admission_identity_out_of_range");
    const auto largest = original_expected_admission({0x89abcdefU,0xfedcba98U,32767}, redirect);
    check(largest.id0 == 0x89abcdefU && largest.id1 == 0xfedcba98U && largest.id2 == 32767,
          "room/game DWORDs or maximum signed16 user ID changed");
    const auto random = original_redirect_with_random_tokens(redirect.endpoint);
    check(random.endpoint.address == redirect.endpoint.address && random.endpoint.port == redirect.endpoint.port,
          "random token generation altered endpoint");
    check(encode_original_game_redirect(random).payload.size() == 18, "generated redirect size differs");
    check(random.token_a <= 0x7fffffffU, "generated token A fails client signed check");
}

}

int main() {
    try {
        redirect_matches_independent_packed_fixture();
        original_admission_matches_independent_client_echo();
        admission_is_bound_to_full_original_descriptor();
        redirect_boundaries();
        std::cout << "PASS original redirect fields and single-use admission binding\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
