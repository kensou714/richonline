#include "richonline_controlled_dice.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
const Bytes card_request{0x67,0,0xcd,0xab,7,0,6,0xff,0,0,0,0};
const Bytes paid_request{0x16,0,0xff,0xff,1,0xe7};
void card_byte_boundaries() {
    // Given an exact sender-sized card request with a nonzero opaque byte.
    const auto request = std::get<RichonlineCardDiceRequest103>(parse_richonline_controlled_dice_request(card_request));
    // Then the adjacent unknown byte cannot turn the one-byte die into a signed WORD.
    check(request.calendar_counter == 0xabcd && request.inventory_slot == 7 && request.inventory_bank == 0 &&
        request.selected_die == 6 && request.opaque7 == 0xff,"card_fields_or_die_width");
    for (std::uint8_t die = 1; die <= 6; ++die) {
        auto bytes = card_request; bytes[6] = die; bytes[7] = static_cast<std::uint8_t>(0x80U+die);
        check(std::get<RichonlineCardDiceRequest103>(parse_richonline_controlled_dice_request(bytes)).selected_die == die,
            "card_die_domain");
    }
}
void paid_route_remains_distinct() {
    const auto request = std::get<RichonlinePaidDiceRequest22>(parse_richonline_controlled_dice_request(paid_request));
    check(request.calendar_counter == 0xffff && request.selected_die == 1 && request.opaque5 == 0xe7,"paid_fields");
    auto last = paid_request; last[4] = 6; last[5] = 0;
    check(std::holds_alternative<RichonlinePaidDiceRequest22>(parse_richonline_controlled_dice_request(last)),"paid_variant");
}
void malformed_requests() {
    for (const auto& valid : {card_request,paid_request}) {
        for (std::size_t length = 0; length < valid.size(); ++length)
            rejects([&] { parse_richonline_controlled_dice_request(View(valid).first(length)); },
                "richonline_controlled_dice_length_invalid");
        auto extra = valid; extra.push_back(0);
        rejects([&] { parse_richonline_controlled_dice_request(extra); },"richonline_controlled_dice_length_invalid");
    }
    auto wrong = card_request; wrong[0] = 0x10;
    rejects([&] { parse_richonline_controlled_dice_request(wrong); },"richonline_controlled_dice_opcode_unsupported");
    for (const auto slot : {8U,128U,255U}) {
        auto bytes = card_request; bytes[4] = static_cast<std::uint8_t>(slot);
        rejects([&] { parse_richonline_controlled_dice_request(bytes); },"richonline_controlled_dice_slot_invalid");
    }
    for (const auto bank : {1U,2U,255U}) {
        auto bytes = card_request; bytes[5] = static_cast<std::uint8_t>(bank);
        rejects([&] { parse_richonline_controlled_dice_request(bytes); },"richonline_controlled_dice_bank_unsupported");
    }
    for (const auto die : {0U,7U,128U,255U}) {
        auto bytes = card_request; bytes[6] = static_cast<std::uint8_t>(die);
        rejects([&] { parse_richonline_controlled_dice_request(bytes); },"richonline_controlled_dice_die_invalid");
        bytes = paid_request; bytes[4] = static_cast<std::uint8_t>(die);
        rejects([&] { parse_richonline_controlled_dice_request(bytes); },"richonline_controlled_dice_die_invalid");
    }
    for (std::size_t offset = 8; offset < 12; ++offset) {
        auto bytes = card_request; bytes[offset] = 1;
        rejects([&] { parse_richonline_controlled_dice_request(bytes); },"richonline_controlled_dice_constructor_extension_unknown");
    }
}
void exact_response_prefixes() {
    check(encode_richonline_card_used40b7({0x2345,7,0}) == Bytes{0xb7,0x40,0x45,0x23,7,0},"card_used_prefix");
    check(encode_richonline_card_used40b7({0,0,0}).size() == 6,"zero_slot_and_id");
    check(encode_richonline_dice_recovery400b(0xabcd) == Bytes{0x0b,0x40,0xcd,0xab,1},"recovery_enable_prefix");
    for (const auto slot : {-1,8,127})
        rejects([&] { encode_richonline_card_used40b7({1,static_cast<std::int8_t>(slot),0}); },
            "richonline_controlled_dice_slot_invalid");
    for (const auto bank : {-1,1,2})
        rejects([&] { encode_richonline_card_used40b7({1,0,static_cast<std::int8_t>(bank)}); },
            "richonline_controlled_dice_bank_unsupported");
}
}
int main() {
    try {
        card_byte_boundaries(); paid_route_remains_distinct(); malformed_requests(); exact_response_prefixes();
        std::cout << "PASS new-client controlled dice requests and response prefixes\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
