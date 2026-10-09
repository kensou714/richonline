#include "original_shop.hpp"
#include "original_card_reward.hpp"
#include <algorithm>
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        if (error.what() != code) throw std::runtime_error("expected "+std::string(code)+", got "+error.what()); return;
    }
    throw std::runtime_error("missing rejection: "+std::string(code));
}
const OriginalShopClock::time_point epoch{};
OriginalShopCatalog catalog() { return {{1038,1044,1069},{500},{{1038,30},{1044,40},{1069,51}},{{1038,1},{1044,7},{1069,1}}}; }
OriginalShop shop(OriginalInventory inventory = make_original_inventory(), std::uint32_t tickets = 500,
    std::optional<std::uint32_t> cost = 5, std::uint32_t reserve = 100) {
    return {{0x3456,7,0,epoch,cost},catalog(),std::make_shared<OriginalCardCombinations>(),{inventory,tickets,reserve},
        [](std::uint32_t) { return 0U; }};
}
void wire_contracts() {
    const auto buy = std::get<OriginalShopChoice>(parse_original_shop_request(Bytes{48,0,0x34,0x12,0xff,0xcc}));
    check(buy.context == 0x1234 && buy.index == -1 && buy.opaque == 0xcc,"48 signed exit and opaque tail");
    const auto sale = std::get<OriginalShopSale>(parse_original_shop_request(Bytes{49,0,7,0,3,0x91}));
    check(sale.slot == 3 && sale.opaque == 0x91,"49 preserves unwritten byte");
    check(std::get<OriginalShopRefresh>(parse_original_shop_request(Bytes{53,0,7,0})).context == 7,"53 has no amount field");
    check(std::get<OriginalCardDiscard>(parse_original_shop_request(Bytes{50,0,7,0,7,0xa5})).slot == 7,"50 is separate discard");
    for (const auto op : {48,49,50,53}) {
        Bytes valid{static_cast<std::uint8_t>(op),0,7,0}; if (op != 53) valid.insert(valid.end(),{0,0xcc});
        for (std::size_t size = 0; size < valid.size(); ++size)
            rejects([&] { parse_original_shop_request(View(valid).first(size)); },"original_shop_request_length_invalid");
        valid.push_back(0); rejects([&] { parse_original_shop_request(valid); },"original_shop_request_length_invalid");
    }
    rejects([] { parse_original_shop_request(Bytes{48,0,7,0,12,0}); },"original_shop_index_invalid");
    rejects([] { parse_original_shop_request(Bytes{49,0,7,0,255,0}); },"original_shop_inventory_slot_invalid");
    rejects([] { parse_original_shop_request(Bytes{51,0,7,0}); },"original_shop_opcode_unsupported");
    OriginalShopStock stock{0x3456,{},true}; stock.slots.fill({-1,0,{0x81,0xa7}}); stock.slots[0] = {1038,2,{0x23,0xfe}};
    Bytes expected{0x30,0x40,0x56,0x34,0x0e,4,2,0,0x23,0xfe};
    for (int row = 1; row < 12; ++row) expected.insert(expected.end(),{0xff,0xff,0,0,0x81,0xa7}); expected.push_back(1);
    check(encode_original_shop_stock(stock) == expected,"4030 complete twelve six-byte slots and independent tails");
    check(encode_original_shop_choice(0x3456,-1) == Bytes{0x31,0x40,0x56,0x34,255},"4031 exit");
    check(encode_original_shop_sale(0x3456,7) == Bytes{0x32,0x40,0x56,0x34,7},"4032 slot only");
    check(encode_original_card_discard(0x3456,6,2) == Bytes{0x33,0x40,0x56,0x34,6,2},"4033 explicit owner");
    check(encode_original_card_grant(0x3456,1044) == Bytes{0x29,0x40,0x56,0x34,0x14,4},"4029 card id");
}
void buy_sell_and_discard() {
    auto inventory = make_original_inventory(); inventory[0].opaque = {0x73,0x82};
    auto visit = shop(inventory);
    const auto stock = visit.open_message();
    check(stock.size() == 77 && stock[8] == 0 && stock[9] == 255 && stock.back() == 0,"stock uses proven constructor tails, open flag");
    auto bought = visit.handle(OriginalShopChoice{7,1,0xcc},epoch);
    check(bought.messages == std::vector<Bytes>{{0x31,0x40,0x56,0x34,1}} && visit.wallet().tickets == 460 &&
        visit.wallet().inventory[0] == OriginalCardSlot{1044,7,{0x73,0x82}},"buy stack count7 costs once and preserves destination tail");
    auto sold = visit.handle(OriginalShopSale{7,0,0xcc},epoch);
    check(sold.messages == std::vector<Bytes>{{0x32,0x40,0x56,0x34,0}} && visit.wallet().tickets == 480 &&
        visit.wallet().inventory[0] == OriginalCardSlot{-1,0,{0x73,0x82}},"sell whole stack refunds once");
    visit.handle(OriginalShopChoice{7,2,0},epoch);
    const auto discarded = visit.handle(OriginalCardDiscard{7,0,0xcc},epoch);
    const auto repeated = visit.handle(OriginalCardDiscard{7,0,0x91},epoch);
    check(discarded.messages == repeated.messages && visit.wallet().tickets == 429 && visit.wallet().account_reserve == 100,
        "discard is idempotent without sale refund or account charge");
}
void refusals_close_without_refresh_charge() {
    auto low = shop(make_original_inventory(),1);
    const auto result = low.handle(OriginalShopChoice{7,0,0xcc},epoch);
    check(result.closed && result.rejection == "original_shop_insufficient_tickets" && result.messages.at(0)[0] == 0x31 &&
        low.wallet().account_reserve == 100 && low.wallet().tickets == 1,"rejection closes, never paid refresh");
    auto full = make_original_inventory(); full.fill({1044,1,{0,255}});
    auto busy = shop(full); const auto refused = busy.handle(OriginalShopChoice{7,0,0},epoch);
    check(refused.closed && refused.rejection == "original_shop_inventory_full" && busy.wallet().inventory == full,"full bag not charged");
    auto repeat = shop(); repeat.handle(OriginalShopChoice{7,0,0},epoch);
    check(repeat.handle(OriginalShopChoice{7,0,0},epoch).rejection == "original_shop_offer_empty" && repeat.wallet().tickets == 470,
        "duplicate sold offer cannot grant or debit twice");
    auto unknown = shop(make_original_inventory(),500,{});
    check(unknown.handle(OriginalShopRefresh{7},epoch).rejection == "original_shop_refresh_price_unrecovered" && unknown.wallet().account_reserve == 100,
        "missing effective fee does not mean free refresh");
}
void paid_refresh_and_fixed_deadline() {
    auto visit = shop(); const auto end = visit.deadline();
    const auto refresh = visit.handle(OriginalShopRefresh{7},epoch+std::chrono::seconds(9));
    check(refresh.messages.at(0).size() == 77 && refresh.messages.at(0).back() == 1 &&
        visit.wallet().account_reserve == 95 && refresh.account_charge == 5 && visit.wallet().tickets == 500 && visit.deadline() == end,
        "refresh charges account resource and preserves deadline");
    check(visit.poll(end-std::chrono::milliseconds(1)).messages.empty(),"early poll keeps visit");
    check(visit.poll(end).closed && visit.poll(end).messages.empty(),"deadline closes exactly once");
    check(visit.handle(OriginalShopChoice{7,-1,0xcc},end).messages.empty(),"late same-context exit idempotent");
    rejects([&] { visit.handle(OriginalShopChoice{8,-1,0xcc},end); },"original_shop_context_mismatch");
    auto limited = shop();
    for (int i = 0; i < 5; ++i) check(!limited.handle(OriginalShopRefresh{7},epoch).closed,"five refreshes accepted");
    check(limited.handle(OriginalShopRefresh{7},epoch).rejection == "original_shop_refresh_limit" && limited.wallet().account_reserve == 75,"sixth refresh rejected without charge");
    auto at_end = shop();
    check(at_end.handle(OriginalShopChoice{7,0,0},end).closed && at_end.wallet().tickets == 500,"request at deadline cannot purchase");
    auto poor = shop(make_original_inventory(),500,5,4);
    const auto denied = poor.handle(OriginalShopRefresh{7},epoch);
    check(denied.closed && denied.account_charge == 0 && poor.wallet().account_reserve == 4,"insufficient account reserve does not charge");
}
void synthesis_and_actual_resources() {
    constexpr std::u8string_view path = RICHONLINE_LEGACY_RESOURCE_ROOT;
    const auto root = std::filesystem::path(std::u8string(path.begin(),path.end()));
    const auto props = load_original_prop_cards(root/"Data"/"Prop.kpd");
    const auto map = original_map_resources(load_original_emp(root/"Map"/"BS_1_1.emp"),10);
    const auto combinations = std::make_shared<OriginalCardCombinations>(load_original_card_combinations(root/"Data"/"CombCard.kpd"));
    const auto real = original_shop_catalog(props,map);
    check(!real.offers.empty() && real.prices.contains(1038),"catalog loads real KPD and original map");
    for (const auto id : real.offers) {
        const auto found = std::find_if(props.cards.begin(),props.cards.end(),[id](const auto& card) { return card.id == id; });
        check(found != props.cards.end() && found->enabled.value_or(false) && found->sale_g.value_or(false) &&
            real.counts.at(id) == found->fold.value_or(1),"offers use proven Prop enable/sale/fold values");
    }
    auto inventory = make_original_inventory(); for (std::size_t i = 0; i < 7; ++i) inventory[i] = {1044,1,{0x80,0x93}};
    OriginalShop combine({0x3456,7,0,epoch,5},{{1044},{500},{{1044,40}},{{1044,1}}},combinations,{inventory,500,100},[](std::uint32_t) { return 0U; });
    combine.handle(OriginalShopChoice{7,0,0},epoch);
    check(combine.wallet().inventory[0] == OriginalCardSlot{500,1,{0x80,0x93}} && combine.wallet().inventory[7].id == -1 &&
        combine.wallet().tickets == 460,"real combination runs after successful purchase without whitelist");
    const auto reward = grant_original_card(inventory,{0x3456,1044},*combinations,std::array<std::int16_t,1>{500});
    check(reward.inserted && reward.inventory[0].id == 500 && reward.combinations.size() == 1 &&
        reward.message == Bytes{0x29,0x40,0x56,0x34,0x14,4},"card-grant applies real synthesis and still emits continuation");
    auto full = inventory; full[7] = {1038,3,{0x17,0x28}};
    const auto dropped = grant_original_card(full,{0x3456,1044},*combinations,std::array<std::int16_t,1>{500});
    check(!dropped.inserted && dropped.inventory == full && dropped.combinations.empty() && dropped.message == reward.message,
        "full bag card-grant preserves inventory but still sends4029 so client advances landing");
    rejects([&] { grant_original_card(full,{0x3456,-1},*combinations,{}); },"original_card_grant_id_invalid");
    std::cout << "Actual original shop offers=" << real.offers.size() << ", Prop cards=" << props.cards.size() << '\n';
}
}
int main() {
    try {
        wire_contracts(); buy_sell_and_discard(); refusals_close_without_refresh_charge(); paid_refresh_and_fixed_deadline(); synthesis_and_actual_resources();
        std::cout << "PASS original shop wire, balances, fixed slots, combinations, paid refresh and bounded closure.\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
