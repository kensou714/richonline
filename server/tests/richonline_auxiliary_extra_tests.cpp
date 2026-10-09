#include "richonline_auxiliary.hpp"

#include <algorithm>
#include <bit>
#include <iostream>
#include <string>

namespace {
using namespace richnet;
void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
template<class Action> void rejects(Action action, std::string_view reason) {
    try { action(); } catch (const CodecError& error) {
        require(error.what() == reason, "wrong_rejection_reason");
        return;
    }
    throw std::runtime_error("missing_rejection");
}
Bytes request(std::uint32_t type, std::int32_t category, const RichonlineAuxiliaryName* name) {
    Bytes value{13, 10};
    append_le(value, type, 4);
    append_le(value, static_cast<std::uint32_t>(category), 4);
    if (name) value.insert(value.end(), name->begin(), name->end());
    return value;
}
void run() {
    const auto alice = richonline_auxiliary_name("alice");
    const auto bob = richonline_auxiliary_name("bob");
    for (const auto type : {0U, 1U, 2U}) {
        const auto packet = request(type, -17, type == 1 ? nullptr : &alice);
        for (std::size_t n = 0; n < packet.size(); ++n)
            require(!decode_richonline_inquiry_request(View(packet).first(n)), "partial_inquiry_accepted");
        const auto decoded = decode_richonline_inquiry_request(packet);
        require(decoded && static_cast<std::uint32_t>(decoded->type) == type && decoded->category == -17,
            "inquiry_field_mismatch");
        require(type == 1 ? !decoded->name : decoded->name == alice, "inquiry_name_mismatch");
        auto extra = packet; extra.push_back(0);
        rejects([&] { decode_richonline_inquiry_request(extra); }, "richonline_inquiry_trailing_bytes");
    }
    auto unknown = request(3, 9, nullptr);
    rejects([&] { decode_richonline_inquiry_request(unknown); }, "richonline_inquiry_wire_type_unknown");
    unknown[0] = 12;
    rejects([&] { decode_richonline_inquiry_request(unknown); }, "richonline_auxiliary_bad_magic");
    const auto intro = request(0, 32, &bob);
    for (std::size_t n = 0; n < intro.size(); ++n)
        require(!decode_richonline_intro_request(View(intro).first(n)), "partial_intro_accepted");
    require(decode_richonline_intro_request(intro) == bob, "intro_name_mismatch");
    auto wrong_size = intro; wrong_size[6] = 31;
    rejects([&] { decode_richonline_intro_request(wrong_size); }, "richonline_intro_name_length_invalid");
    const RichonlineRankValue self{alice, 7};
    const RichonlineRankValue row{bob, 11};
    std::vector<RichonlineRankValue> rows(100, row);
    const auto ranking = encode_richonline_named_ranking(-1, self, rows);
    require(ranking.size() == 3652 && read_le(View(ranking).subspan(4, 4)) == 3644, "named_rank_max_size");
    require(read_le(View(ranking).subspan(8, 4)) == 0xffffffffU, "named_rank_signed");
    require(read_le(View(ranking).subspan(44, 4)) == 7 && read_le(View(ranking).subspan(48, 4)) == 100,
        "named_rank_field_offsets");
    require(std::equal(bob.begin(), bob.end(), ranking.begin() + 52), "named_rank_first_row");
    rows.push_back(row);
    rejects([&] { encode_richonline_named_ranking(1, self, rows); }, "richonline_inquiry_row_limit");
    std::vector<RichonlineRankColumns> columns(100, {bob, {13, 27, -9}});
    const auto table = encode_richonline_category_ranking(columns);
    require(table.size() == 4412 && read_le(View(table).subspan(4, 4)) == 4404, "rank_columns_max_size");
    require(read_le(View(table).subspan(44, 4)) == 13 && read_le(View(table).subspan(48, 4)) == 27 &&
        std::bit_cast<std::int32_t>(read_le(View(table).subspan(52, 4))) == -9, "rank_columns_offsets");
    require(encode_richonline_category_ranking({}).size() == 12, "empty_dataset_not_encoded");
    for (const auto rank : {-1, 1, 10000}) {
        const auto search = encode_richonline_rank_search(rank);
        require(search.size() == 12 && std::bit_cast<std::int32_t>(read_le(View(search).subspan(8, 4))) == rank,
            "rank_search_result");
    }
    for (const auto rank : {-2, 0, 10001})
        rejects([&] { encode_richonline_rank_search(rank); }, "richonline_inquiry_search_result_invalid");
    require(encode_richonline_intro(alice, {}).size() == 40, "empty_intro_not_encoded");
    const auto profile = encode_richonline_intro(alice, Bytes(400, 'x'));
    require(profile.size() == 440 && read_le(View(profile).subspan(4, 4)) == 432, "intro_max_size");
    rejects([&] { encode_richonline_intro(alice, Bytes(401, 'x')); }, "richonline_intro_text_too_long");
    rejects([&] { encode_richonline_intro(alice, Bytes{0x80}); }, "richonline_auxiliary_text_invalid_byte");
    rejects([&] { encode_richonline_intro(alice, Bytes{0xa4}); }, "richonline_auxiliary_text_incomplete_pair");
    require(encode_richonline_intro(alice, Bytes{0xa4, 0x40}).size() == 42, "two_byte_intro_rejected");
    for (const auto type : {0U, 1U}) {
        Bytes channel{13, 10}; append_le(channel, type, 4);
        require(decode_richonline_aux_channel_request(channel) == type, "aux_channel_request");
        channel.push_back(0);
        rejects([&] { decode_richonline_aux_channel_request(channel); }, "richonline_aux_channel_trailing_bytes");
    }
    require(richonline_auxiliary_name(std::string(32, 'a'))[31] == 'a', "full_name_width");
    rejects([&] { richonline_auxiliary_name(std::string(33, 'a')); }, "richonline_auxiliary_name_invalid");
}
}
int main() {
    try { run(); std::cout << "richonline auxiliary extra tests passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
