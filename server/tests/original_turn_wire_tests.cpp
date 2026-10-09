#include "original_turn_wire.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool condition,std::string_view reason) { if (!condition) throw std::runtime_error(std::string(reason)); }
template<class Action> void rejects(Action action,std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,"unexpected turn wire rejection"); return; }
    throw std::runtime_error("expected rejection missing");
}
OriginalInitialCards initial_cards() {
    return {0xa173,7,{{{1044,2,{0xa1,0xb1}},{1038,1,{0xa2,0xb2}},{-1,0,{0,255}},{32767,32767,{0xca,0xfe}}}},{0xcc,0xdd}};
}
void exact_vectors() {
    check(encode_original_turn_start({0xa173,7,3,{0xcc,0x91}}) == Bytes{0x10,0x40,0x73,0xa1,7,3,0,0xcc,0x91},
          "normal turn writes separate slots, explicit normal flag and opaque suffix");
    check(encode_original_boss_turn_resume({0xa173,{0xcc,0x92}}) == Bytes{0x0f,0x42,0x73,0xa1,0xff,0xff,0xcc,0x92},
          "no-lottery continuation writes signed minus-one tile and explicit suffix");
    const Bytes expected{0x19,0x40,0x73,0xa1,7,0,0x14,4,2,0,0xa1,0xb1,0x0e,4,1,0,0xa2,0xb2,
        0xff,0xff,0,0,0,0xff,0xff,0x7f,0xff,0x7f,0xca,0xfe,0xcc,0xdd};
    check(encode_original_initial_cards(initial_cards()) == expected,"4019 writes precisely four six-byte records preserving each tail");
    for (const auto& plain : {encode_original_turn_start({0xffff,0,0,{}}),encode_original_boss_turn_resume({0xffff,{}}),expected})
        check(decode_inner(encode_inner(plain,Bytes(plain.size()+2,0x97))) == plain,"turn payloads survive existing inner codec");
    check(encode_original_turn_start({0,0,0,{}}).size() == 7 && encode_original_boss_turn_resume({0,{}}).size() == 6,
          "no inferred alignment or unspecified tail appended");
}
void boundaries() {
    for (const auto invalid : {std::uint8_t{8},std::uint8_t{255}}) {
        rejects([&] { encode_original_turn_start({1,invalid,0,{}}); },"original_turn_slot_invalid");
        rejects([&] { encode_original_turn_start({1,0,invalid,{}}); },"original_turn_slot_invalid");
    }
    auto cards = initial_cards();
    for (const std::int16_t owner : {std::int16_t{-1},std::int16_t{8}}) {
        cards.owner = owner;
        rejects([&] { encode_original_initial_cards(cards); },"original_initial_cards_owner_invalid");
    }
    cards = initial_cards(); cards.slots[1] = {-1,1,{0xa2,0xb2}};
    rejects([&] { encode_original_initial_cards(cards); },"original_inventory_slot_invalid");
    cards = initial_cards(); cards.slots[2] = {1,0,{0xa3,0xb3}};
    rejects([&] { encode_original_initial_cards(cards); },"original_inventory_slot_invalid");
    check(encode_original_turn_start({1,7,7,Bytes(502,0x55)}).size() == 509,"turn suffix max");
    check(encode_original_boss_turn_resume({1,Bytes(503,0x66)}).size() == 509,"resume suffix max");
    cards = initial_cards(); cards.opaque_suffix.assign(479,0x77);
    check(encode_original_initial_cards(cards).size() == 509,"initial four-slot suffix max");
    rejects([] { encode_original_turn_start({1,0,0,Bytes(503)}); },"original_turn_plain_too_large");
    rejects([] { encode_original_boss_turn_resume({1,Bytes(504)}); },"original_turn_plain_too_large");
    cards.opaque_suffix.push_back(0x77);
    rejects([&] { encode_original_initial_cards(cards); },"original_turn_plain_too_large");
}
}
int main() {
    try { exact_vectors(); boundaries(); std::cout << "PASS original normal turn, no-lottery resume and initial four-card wire encodings\n"; }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
