#include "richonline_game_end.hpp"

#include <iostream>
#include <stdexcept>

namespace {
void check(bool ok, const char* what) {
    if (!ok) throw std::runtime_error(what);
}
template<class Fn> void rejects(Fn fn, const char* what) {
    try { fn(); } catch (const richnet::CodecError&) { return; }
    throw std::runtime_error(what);
}
}

int main() {
    using namespace richnet;
    try {
        validate_richonline_leave_request(Bytes{0x0a, 0x00});
        rejects([] { validate_richonline_leave_request(Bytes{}); }, "short leave");
        rejects([] { validate_richonline_leave_request(Bytes{0x0a, 0x00, 0}); }, "extended leave");
        rejects([] { validate_richonline_leave_request(Bytes{0x0b, 0x00}); }, "wrong leave opcode");
        check(richonline_leave_ack(0x1234) == Bytes({6, 0x40, 0x34, 0x12}), "leave ack");
        check(richonline_stop_game_controls(0x1234) == Bytes({12, 0x40, 0x34, 0x12}), "stop");
        check(richonline_bankruptcy_notice(0x1234, 7) == Bytes({13, 0x40, 0x34, 0x12, 7}), "bankruptcy");
        check(richonline_eliminate_actor(0x1234, 0) == Bytes({14, 0x40, 0x34, 0x12, 0}), "elimination");
        check(richonline_show_game_results(0x1234, true) == Bytes({15, 0x40, 0x34, 0x12, 1}), "results UI");
        rejects([] { (void)richonline_bankruptcy_notice(1, -1); }, "negative actor");
        rejects([] { (void)richonline_eliminate_actor(1, 8); }, "ninth actor");

        // Independent byte fixture exercises signed loads and nonzero unknown
        // fields so a zero-filled encoder cannot pass this contract.
        const Bytes fixture{0x1b, 0x40, 0x34, 0x12, 7, 0xff, 0xfe, 0xff,
                            0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89,
                            2, 0x87, 0x69, 3};
        const auto record = decode_richonline_game_result(fixture);
        check(record.game_id == 0x1234 && record.actor == 7, "record identity");
        check(record.rank_image_index == -1 && record.experience_award == -2, "signed result fields");
        check(record.returned_gold == 0x12345678 && record.bonus_gold == 0x89abcdef, "result dwords");
        check(record.winner_flag == 2 && record.escaped_flag == 0x87 && record.opaque_18 == 0x69 && record.level_up_flag == 3, "opaque preservation");
        check(encode_richonline_game_result(record) == fixture, "result encoding");
        for (std::size_t length = 0; length < fixture.size(); ++length) {
            rejects([&] { (void)decode_richonline_game_result(View(fixture).first(length)); }, "truncated result");
        }
        auto invalid = fixture;
        invalid.push_back(0);
        rejects([&] { (void)decode_richonline_game_result(invalid); }, "extended result");
        invalid = fixture;
        invalid[4] = 0xff;
        rejects([&] { (void)decode_richonline_game_result(invalid); }, "invalid result actor");
        invalid = fixture;
        invalid[0] = 0x1a;
        rejects([&] { (void)decode_richonline_game_result(invalid); }, "wrong result opcode");
        std::cout << "richonline_game_end_tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
