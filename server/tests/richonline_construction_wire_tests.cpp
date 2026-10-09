#include "richonline_construction_wire.hpp"
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        check(error.what() == code,"wrong_rejection"); return;
    }
    throw std::runtime_error("invalid_input_accepted");
}
void request_preserves_signed_choices_counter_and_opaque() {
    for (const auto selection : {-1,10,11,12,13,14,15,16,17,18,19,20}) {
        const Bytes plain{0x37,0,0xff,0xff,static_cast<std::uint8_t>(selection),0xa5};
        const auto result = decode_richonline_construction_request(plain);
        check(result.calendar == 65535 && result.selection == selection && result.opaque_tail == 0xa5,
            "request_fields_wrong");
    }
}
void malformed_request_is_rejected() {
    const Bytes plain{0x37,0,0x34,0x12,11,0xcc};
    for (std::size_t n = 0; n < 6; ++n)
        rejects([&] { decode_richonline_construction_request(View(plain).first(n)); },"richonline_construction_request_size");
    rejects([] { decode_richonline_construction_request(Bytes{0x37,0,0,0,11,0,0}); },"richonline_construction_request_size");
    for (const auto opcode : {0x0038,0x0137}) {
        auto changed = plain; changed[0] = static_cast<std::uint8_t>(opcode); changed[1] = static_cast<std::uint8_t>(opcode >> 8);
        rejects([&] { decode_richonline_construction_request(changed); },"richonline_construction_request_opcode");
    }
    for (const auto selection : {0,9,21,127,128,254}) {
        auto changed = plain; changed[4] = static_cast<std::uint8_t>(selection);
        rejects([&] { decode_richonline_construction_request(changed); },"richonline_construction_selection_invalid");
    }
}
void response_emits_only_resolved_consumed_prefix() {
    check(richonline_construction_response(0x1234,11) == Bytes{0x3d,0x40,0x34,0x12,11},"build_response_wrong");
    check(richonline_construction_response(0xffff,10) == Bytes{0x3d,0x40,0xff,0xff,10},"decline_response_wrong");
    check(richonline_construction_response(0,20) == Bytes{0x3d,0x40,0,0,20},"boundary_response_wrong");
    for (const auto choice : {-128,-1,0,9,21,127})
        rejects([&] { richonline_construction_response(1,static_cast<std::int8_t>(choice)); },"richonline_construction_response_selection_invalid");
}
void upgrade_request_preserves_choices_counter_and_opaque() {
    for (const auto accept : {0,1}) {
        const Bytes plain{0x38,0,0xff,0xff,static_cast<std::uint8_t>(accept),0xa5};
        const auto result = decode_richonline_upgrade_request(plain);
        check(result.calendar == 65535 && result.accept == (accept == 1) && result.opaque_tail == 0xa5,
            "upgrade_request_fields_wrong");
    }
}
void malformed_upgrade_request_is_rejected() {
    const Bytes plain{0x38,0,0x34,0x12,1,0xcc};
    for (std::size_t n = 0; n < 6; ++n)
        rejects([&] { decode_richonline_upgrade_request(View(plain).first(n)); },"richonline_upgrade_request_size");
    rejects([] { decode_richonline_upgrade_request(Bytes{0x38,0,0,0,1,0,0}); },"richonline_upgrade_request_size");
    for (const auto opcode : {0x0037,0x0138}) {
        auto changed = plain; changed[0] = static_cast<std::uint8_t>(opcode); changed[1] = static_cast<std::uint8_t>(opcode >> 8);
        rejects([&] { decode_richonline_upgrade_request(changed); },"richonline_upgrade_request_opcode");
    }
    for (const auto accept : {2,127,128,255}) {
        auto changed = plain; changed[4] = static_cast<std::uint8_t>(accept);
        rejects([&] { decode_richonline_upgrade_request(changed); },"richonline_upgrade_accept_invalid");
    }
}
void upgrade_response_encodes_both_outcomes() {
    check(richonline_upgrade_response(0x1234,true) == Bytes{0x3e,0x40,0x34,0x12,1},"upgrade_response_wrong");
    check(richonline_upgrade_response(0xffff,false) == Bytes{0x3e,0x40,0xff,0xff,0},"upgrade_decline_response_wrong");
}
void research_fields_and_boundaries() {
    for(const auto choice:{-1,1,2,3,4,5,6,7}) {
        const Bytes plain{0x39,0,0xff,0xff,static_cast<std::uint8_t>(choice),0xa5};
        const auto decoded=decode_richonline_research_request(plain);
        check(decoded.calendar==65535 && decoded.selection==choice && decoded.opaque_tail==0xa5,"research_fields_wrong");
        check(richonline_research_response(0x1234,decoded.selection)==Bytes{0x3f,0x40,0x34,0x12,plain[4]},"research_response_wrong");
    }
    for(const auto choice:{0,8,10,127,128,254}) {
        rejects([&]{decode_richonline_research_request(Bytes{0x39,0,0,0,static_cast<std::uint8_t>(choice),0});},
            "richonline_research_selection_invalid");
    }
    for(const auto n:{0,1,2,3,4,5,7})
        rejects([&]{decode_richonline_research_request(Bytes(static_cast<std::size_t>(n)));},"richonline_research_request_size");
    rejects([]{decode_richonline_research_request(Bytes{0x38,0,0,0,1,0});},"richonline_research_request_opcode");
}
}
int main() {
    try { request_preserves_signed_choices_counter_and_opaque(); malformed_request_is_rejected();
        response_emits_only_resolved_consumed_prefix(); upgrade_request_preserves_choices_counter_and_opaque();
        malformed_upgrade_request_is_rejected(); upgrade_response_encodes_both_outcomes();
        research_fields_and_boundaries();
        std::cout << "richonline_construction_wire_tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
