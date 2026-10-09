#include "richonline_property_wire.hpp"
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void rejects(const Bytes& plain, std::string_view reason) {
    try {
        static_cast<void>(decode_richonline_property_request(plain));
    } catch (const CodecError& error) {
        check(error.what() == reason, "wrong_rejection_reason");
        return;
    }
    throw std::runtime_error("invalid_property_request_accepted");
}
void ordinary_purchase_preserves_calendar_and_opaque_tail() {
    const Bytes plain{0x20,0,0x34,0x12,0,0,0,0,1,0xcc,0xa5,0xff};
    const auto request = decode_richonline_property_request(plain);
    check(request.calendar == 0x1234, "calendar_wrong");
    check(request.secondary == 0, "secondary_wrong");
    check(request.accept, "purchase_wrong");
    check(request.opaque_tail == std::array<std::uint8_t,3>{0xcc,0xa5,0xff}, "tail_lost");
}
void ordinary_decline_preserves_calendar_boundary() {
    const Bytes plain{0x20,0,0xff,0xff,0,0,0,0,0,0,0,0};
    const auto request = decode_richonline_property_request(plain);
    check(request.calendar == 0xffff && !request.accept, "decline_wrong");
}
void malformed_size_is_rejected() {
    const Bytes plain{0x20,0,0,0,0,0,0,0,1,0xcc,0xcc,0xcc};
    for (std::size_t size = 0; size < plain.size(); ++size)
        rejects(Bytes(plain.begin(), plain.begin() + static_cast<std::ptrdiff_t>(size)),
            "richonline_property_request_size");
    auto extended = plain;
    extended.push_back(0);
    rejects(extended, "richonline_property_request_size");
}
void wrong_opcode_is_rejected() {
    rejects({0x21,0,0,0,0,0,0,0,1,0,0,0}, "richonline_property_request_opcode");
    rejects({0x20,1,0,0,0,0,0,0,1,0,0,0}, "richonline_property_request_opcode");
}
void nonordinary_secondary_is_rejected() {
    for (const auto offset : {4U,5U,6U,7U}) {
        Bytes plain{0x20,0,0,0,0,0,0,0,1,0,0,0};
        plain[offset] = 1;
        rejects(plain, "richonline_property_secondary_unsupported");
    }
}
void noncanonical_accept_is_rejected() {
    for (const auto accept : {2U,127U,128U,255U}) {
        Bytes plain{0x20,0,0,0,0,0,0,0,0,0,0,0};
        plain[8] = static_cast<std::uint8_t>(accept);
        rejects(plain, "richonline_property_accept_invalid");
    }
}
void response_encodes_consumed_prefix() {
    check(richonline_property_response(0x1234,true) == Bytes{0x20,0x40,0x34,0x12,1}, "buy_response_wrong");
    check(richonline_property_response(0xffff,false) == Bytes{0x20,0x40,0xff,0xff,0}, "decline_response_wrong");
    check(richonline_property_response(0,false) == Bytes{0x20,0x40,0,0,0}, "zero_id_response_wrong");
}
}
int main() {
    try {
        ordinary_purchase_preserves_calendar_and_opaque_tail();
        ordinary_decline_preserves_calendar_boundary();
        malformed_size_is_rejected();
        wrong_opcode_is_rejected();
        nonordinary_secondary_is_rejected();
        noncanonical_accept_is_rejected();
        response_encodes_consumed_prefix();
        std::cout << "richonline_property_wire_tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
