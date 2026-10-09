#include "original_property_wire.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        if (error.what() != code) throw std::runtime_error("expected "+std::string(code)+", got "+error.what()); return;
    }
    throw std::runtime_error("missing rejection: "+std::string(code));
}
void purchase_contract() {
    const Bytes request{32,0,0x78,0x56,0x12,0x34,0x56,0x78,1,0x81,0x92,0xa3};
    const auto decoded = parse_original_property_request(request);
    const auto& purchase = std::get<OriginalPropertyPurchase>(decoded);
    check(purchase.context == 0x5678 && purchase.parameter == 0x78563412 && purchase.choice == 1 &&
        purchase.opaque == std::array<std::uint8_t,3>{0x81,0x92,0xa3},"32 offsets and opaque bytes preserved");
    check(encode_original_property_result(0x1234,decoded) == Bytes{0x20,0x40,0x34,0x12,1},
        "4020 has instance, not request context, and only observed choice extent");
}
void choices_contract() {
    const auto classic = parse_original_property_request(Bytes{33,0,0x78,0x56,0,0xa1});
    check(std::get<OriginalClassicUpgrade>(classic).opaque == 0xa1 &&
        encode_original_property_result(0x1234,classic) == Bytes{0x21,0x40,0x34,0x12,0},"33 differs from56");
    for (std::uint8_t choice = 10; choice <= 20; ++choice) {
        const auto build = parse_original_property_request(Bytes{55,0,0x78,0x56,choice,0xa2});
        check(std::get<OriginalBuildingChoice>(build).context == 0x5678 &&
            encode_original_property_result(0x1234,build) == Bytes{0x3d,0x40,0x34,0x12,choice},"55 kind/cancel");
    }
    const auto upgrade = parse_original_property_request(Bytes{56,0,0x78,0x56,1,0xa3});
    check(std::get<OriginalBossUpgrade>(upgrade).opaque == 0xa3 &&
        encode_original_property_result(0x1234,upgrade) == Bytes{0x3e,0x40,0x34,0x12,1},"56/403E");
    for (const std::uint8_t choice : {255,1,2,3,4,5,6,7}) {
        const auto research = parse_original_property_request(Bytes{57,0,0x78,0x56,choice,0xa4});
        check(std::get<OriginalResearchSelection>(research).opaque == 0xa4 &&
            encode_original_property_result(0x1234,research) == Bytes{0x3f,0x40,0x34,0x12,choice},"57 signed cancel/choice");
    }
}
void malformed_contract() {
    for (const auto op : {32,33,55,56,57}) {
        Bytes packet{static_cast<std::uint8_t>(op),0,7,0};
        if (op == 32) packet.insert(packet.end(),{0,0,0,0,1,0x81,0x92,0xa3});
        else packet.insert(packet.end(),{static_cast<std::uint8_t>(op == 55 ? 11 : 1),0xa4});
        for (std::size_t n = 0; n < packet.size(); ++n)
            rejects([&] { parse_original_property_request(View(packet).first(n)); },"original_property_request_length_invalid");
        packet.push_back(0);
        rejects([&] { parse_original_property_request(packet); },"original_property_request_length_invalid");
    }
    rejects([] { parse_original_property_request(Bytes{56,0,7,0,2,0}); },"original_property_binary_choice_invalid");
    rejects([] { parse_original_property_request(Bytes{55,0,7,0,9,0}); },"original_property_building_choice_invalid");
    rejects([] { parse_original_property_request(Bytes{57,0,7,0,0,0}); },"original_property_research_choice_invalid");
    rejects([] { parse_original_property_request(Bytes{54,0,7,0,1,0}); },"original_property_opcode_unsupported");
    rejects([] { encode_original_property_result(1,OriginalResearchSelection{7,8,0}); },"original_property_research_choice_invalid");
}
}
int main() {
    try { purchase_contract(); choices_contract(); malformed_contract();
        std::cout << "PASS original property request fields, signed choices and response extent.\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
