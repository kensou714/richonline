#include "original_card_resources.hpp"
#include "original_game_values.hpp"
#include <algorithm>
#include <functional>
#include <iostream>

namespace {
using namespace richnet;
Bytes bytes(std::string_view text) { return Bytes(text.begin(),text.end()); }
void check(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        check(error.what() == code,std::string("unexpected rejection: ")+error.what()); return;
    }
    throw std::runtime_error("expected rejection missing");
}
void test_prop_preservation_and_missing_values() {
    const auto source = bytes("; header\r\n[PROP]\r\nindx=38\r\ntype=CARD\r\nname=\xd2\xa3\xbf\xd8\r\n"
        "desc=left=right:detail\r\ncustomOpaque = 9,7\r\n[PROP]\r\nindx=7\r\ntype=FUNC\r\n");
    const auto parsed = parse_original_prop_cards(source);
    check(parsed.decoded == source && parsed.cards.size() == 1,"decoded bytes and CARD filtering");
    const auto& card = parsed.cards.front();
    check(card.id == 38 && !card.enabled && !card.sale_g && !card.price_g && !card.fold,"missing fields retain absence");
    check(card.source_fields.at("name") == "\xd2\xa3\xbf\xd8" && card.source_fields.at("desc") == "left=right:detail" &&
        card.source_fields.at("customOpaque") == "9,7","raw GBK and unknown values preserved");
    const auto explicit_values = parse_original_prop_cards(bytes("[PROP]\nindx:32767\ntype:CARD\nenable:TRUE\nsaleG:true\npriceG:-2147483648\nfold:3\n"));
    const auto& explicit_card = explicit_values.cards.front();
    check(explicit_card.enabled == false && explicit_card.sale_g == true && explicit_card.price_g == -2147483647-1 && explicit_card.fold == 3,
        "exact boolean comparison and signed price/fold source values");
    const auto commas = parse_original_prop_cards(bytes("[PROP]\nindx=1\ntype=CARD\nenable=true,other\nsaleG=true,other\n"));
    check(commas.cards[0].enabled == true && commas.cards[0].sale_g == false,"enable compares first component; saleG compares fullvalue");
    const auto wrong_case = parse_original_prop_cards(bytes("[PROP]\nindx=1\ntype=CARD\nENABLE=true\nPriceG=88\n"));
    check(!wrong_case.cards[0].enabled && !wrong_case.cards[0].price_g && wrong_case.cards[0].source_fields.at("PriceG") == "88",
        "source lookup is case sensitive and unknown fields survive");
}
void test_prop_rejections() {
    for (const auto text : {"", "[PROP]\n", "[PROP]\n[PROP]\nindx=1\ntype=CARD", "// comment only"})
        rejects([&] { parse_original_prop_cards(bytes(text)); }, text[0] == '\0' ? "original_card_text_invalid" : "original_card_records_invalid");
    rejects([&] { parse_original_prop_cards(bytes("[ITEM]\nindx=1\ntype=CARD")); },"original_card_section_invalid");
    rejects([&] { parse_original_prop_cards(bytes("indx=1\n[PROP]\ntype=CARD")); },"original_card_field_invalid");
    rejects([&] { parse_original_prop_cards(bytes("[PROP]\nindx=1\nindx=2\ntype=CARD")); },"original_card_field_duplicate");
    rejects([&] { parse_original_prop_cards(bytes("[PROP]\nindx=1\ntype=CARD\n[PROP]\nindx=1\ntype=FUNC")); },"original_card_id_duplicate");
    rejects([&] { parse_original_prop_cards(bytes("[PROP]\nindx=1")); },"original_card_field_missing");
    for (const auto value : {"-1", "1.5", "+2", "false", "1junk"})
        rejects([&] { parse_original_prop_cards(bytes("[PROP]\nindx="+std::string(value)+"\ntype=CARD")); },"original_card_integer_invalid");
    for (const auto value : {"32768", "999999999999999999999"})
        rejects([&] { parse_original_prop_cards(bytes("[PROP]\nindx="+std::string(value)+"\ntype=CARD")); },"original_card_integer_range");
    rejects([&] { parse_original_prop_cards(bytes("[PROP]\nindx=0\ntype=CARD")); },"original_card_id_invalid");
    const auto booleans = parse_original_prop_cards(bytes("[PROP]\nindx=1\ntype=CARD\nenable=1\nsaleG=TRUE\n"));
    check(booleans.cards[0].enabled == false && booleans.cards[0].sale_g == false,"nontrue strings follow exact client comparison");
    rejects([&] { parse_original_prop_cards(bytes("[PROP]\nindx=1\ntype=CARD\npriceG=2147483648")); },"original_card_integer_range");
    auto nul = bytes("[PROP]\nindx=1\ntype=CARD"); nul.push_back(0);
    rejects([&] { parse_original_prop_cards(nul); },"original_card_text_invalid");
    rejects([&] { parse_original_prop_cards(Bytes(4U*1024U*1024U+1U,' ')); },"original_card_text_invalid");
}
void test_combination_fields_and_order() {
    const auto source = bytes("[ITEM]\nsrc7=700,2147483647\nsrc0=22,3\ndest=811\nenable=true\nunknown=opaque\n[ITEM]\nsrc0=55,2147483647\ndest=911\nenable=TRUE\n");
    const auto parsed = parse_original_card_combinations(source);
    check(parsed.decoded == source && parsed.items.size() == 2,"combination bytes and file order preserved");
    const auto& first = parsed.items[0];
    check(first.destination == 811 && first.enabled == true && first.sources[0] == OriginalCombinationSource{22,3} &&
        !first.sources[7] && !first.sources[1] && first.source_fields.at("src7") == "700,2147483647" &&
        first.source_fields.at("unknown") == "opaque","first source hole ends active list but raw later and unknown fields survive");
    check(parsed.items[1].destination == 911 && parsed.items[1].enabled == false &&
        parsed.items[1].sources[0] == OriginalCombinationSource{55,2147483647},"destination has no legacy whitelist; counts retainint32");
    const auto repeated = parse_original_card_combinations(bytes("[ITEM]\nsrc0=1,1\nsrc1=1,2\ndest=500\nenable=true\n"
        "[ITEM]\nsrc0=1,1\nsrc1=1,2\ndest=501\nenable=true\n"));
    check(repeated.items.size() == 2 && repeated.items[0].sources[1] == OriginalCombinationSource{1,2} &&
        repeated.items[1].destination == 501,"duplicate ingredient IDs and recipes retain sourceorder for client algorithm");
}
void test_combination_rejections() {
    rejects([&] { parse_original_card_combinations(bytes("[ITEM]\ndest=500\nenable=true")); },"original_combination_source_missing");
    rejects([&] { parse_original_card_combinations(bytes("[ITEM]\nsrc0=1,1")); },"original_card_field_missing");
    rejects([&] { parse_original_card_combinations(bytes("[ITEM]\nsrc0=1,1\ndest=500")); },"original_card_field_missing");
    rejects([&] { parse_original_card_combinations(bytes("[ITEM]\nsrc0=1,1\nsrc0=2,1\ndest=500\nenable=true")); },"original_card_field_duplicate");
    for (const auto value : {"1", "1,1,1", "1,0"})
        rejects([&] { parse_original_card_combinations(bytes("[ITEM]\nsrc0="+std::string(value)+"\ndest=500\nenable=true")); },"original_combination_source_invalid");
    rejects([&] { parse_original_card_combinations(bytes("[ITEM]\nsrc0=1,-1\ndest=500\nenable=true")); },"original_card_integer_invalid");
    rejects([&] { parse_original_card_combinations(bytes("[ITEM]\nsrc0=1,2147483648\ndest=500\nenable=true")); },"original_card_integer_range");
}
void test_game_values() {
    const auto raw = bytes("[ITEM]\nindx=260\nvalue=-2147483648\nopaque=\xd2\xa3\n[ITEM]\nindx=0\nvalue=36\n");
    const auto parsed = parse_original_game_values(raw);
    check(parsed.decoded == raw && parsed.require(260) == -2147483647-1 && parsed.require(0) == 36 &&
        parsed.entries.at(260).source_fields.at("opaque") == "\xd2\xa3","GValue preserves signedint32 and raw unknownfields");
    rejects([&] { parsed.require(261); },"original_game_value_missing");
    rejects([&] { parse_original_game_values(bytes("[ITEM]\nindx=-1\nvalue=1")); },"original_game_value_index_invalid");
    rejects([&] { parse_original_game_values(bytes("[ITEM]\nindx=260\nvalue=2147483648")); },"original_game_value_integer_range");
    rejects([&] { parse_original_game_values(bytes("[ITEM]\nindx=260\nvalue=1x")); },"original_game_value_integer_invalid");
    rejects([&] { parse_original_game_values(bytes("[ITEM]\nindx=260\nvalue=1\nvalue=2")); },"original_game_value_field_duplicate");
    rejects([&] { parse_original_game_values(bytes("[ITEM]\nindx=260\nvalue=1\n[ITEM]\nindx=260\nvalue=2")); },"original_game_value_index_duplicate");
    rejects([&] { parse_original_game_values(bytes("[ITEM]\nindx=260")); },"original_game_value_field_missing");
}
void test_actual_resources() {
    constexpr std::string_view source_path = __FILE__;
    const auto root = std::filesystem::path(std::u8string(source_path.begin(),source_path.end())).parent_path().parent_path().parent_path();
    const auto prop = load_original_prop_cards(root / "Data" / "Prop.kpd");
    check(prop.cards.size() == 100,"original decoded Prop.txt oracle contains100 CARD records");
    const auto remote = std::find_if(prop.cards.begin(),prop.cards.end(),[](const auto& card) { return card.id == 1038; });
    check(remote != prop.cards.end() && remote->enabled == true && remote->sale_g == true && remote->price_g == 25,
        "Prop.txt lines2007..2018 remote die typed fields");
    check(remote->source_fields.at("name") == "\xd2\xa3\xbf\xd8\xc9\xab\xd7\xd3" &&
        remote->source_fields.at("ratioCM") == "7" && remote->source_fields.at("ROLE9") == "true",
        "original GBK remote die name and noncorefields remainavailable");
    const auto mine = std::find_if(prop.cards.begin(),prop.cards.end(),[](const auto& card) { return card.id == 1044; });
    check(mine != prop.cards.end() && mine->price_g == 30,"Prop.txt line2235 mineprice");
    const auto combinations = load_original_card_combinations(root / "Data" / "CombCard.kpd");
    const auto game_values = load_original_game_values(root / "Data" / "GValue.kpd");
    check(game_values.require(0) == 36 && game_values.require(19) == 3,"original GValue independent oracle bomb36 and mine3");
    const auto refresh = game_values.entries.find(260);
    if (refresh == game_values.entries.end()) {
        rejects([&] { game_values.require(260); },"original_game_value_missing");
        std::cout << "Original Data/GValue.kpd entries=" << game_values.entries.size() << " refresh index260=missing\n";
    } else std::cout << "Original Data/GValue.kpd entries=" << game_values.entries.size() << " refresh index260=" << refresh->second.value << '\n';
    const std::array<std::int16_t,12> destinations{500,504,505,508,1052,1078,506,1072,1121,1122,501,1123};
    const std::array<std::int16_t,12> sources{1044,1038,1062,1069,1070,1048,1181,1047,1058,1035,1045,1120};
    const std::array<std::int32_t,12> counts{8,8,8,3,2,3,4,3,3,3,3,3};
    check(combinations.items.size() == destinations.size(),"CombCard.txt independentoracle has12recipes");
    for (std::size_t index = 0; index < destinations.size(); ++index) {
        const auto& item = combinations.items[index];
        check(item.destination == destinations[index] && item.sources[0] == OriginalCombinationSource{sources[index],counts[index]} &&
            item.enabled == true,"every original recipe retains order/source/destination/enable");
        for (std::size_t slot = 1; slot < item.sources.size(); ++slot) {
            if (index == 4 && slot == 1) check(item.sources[slot] == OriginalCombinationSource{1051,1},"two-material recipe taxcard");
            else check(!item.sources[slot],"missing recipe slots remain absent");
        }
    }
}
}
int main() {
    try {
        test_prop_preservation_and_missing_values(); test_prop_rejections();
        test_combination_fields_and_order(); test_combination_rejections(); test_game_values(); test_actual_resources();
        std::cout << "PASS original Prop and CombCard KPD, raw GBK fields, optional data and malformed boundaries.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
