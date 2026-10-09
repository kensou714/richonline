#include "original_shop.hpp"
#include <algorithm>
#include <limits>
#include <set>

namespace richnet {
OriginalShopCatalog original_shop_catalog(const OriginalPropCards& props, const OriginalMapResources& map) {
    OriginalShopCatalog result;
    std::set<std::int16_t> allowed;
    for (const auto& row : map.card_weights) {
        if (!allowed.insert(row.card).second) throw CodecError("original_shop_map_card_duplicate");
        result.combination_outputs.push_back(row.card);
    }
    for (const auto& card : props.cards) {
        const auto price = card.price_g.value_or(0);
        if (card.id < 0 || price < 0 || !result.prices.emplace(card.id,price).second)
            throw CodecError("original_shop_card_price_invalid");
        if (allowed.contains(card.id) && card.enabled.value_or(false) && card.sale_g.value_or(false)) {
            const auto count = card.fold.value_or(1);
            if (count < 1 || count > 32767) throw CodecError("original_shop_card_count_invalid");
            result.offers.push_back(card.id);
            result.counts.emplace(card.id,static_cast<std::int16_t>(count));
        }
    }
    if (result.offers.empty()) throw CodecError("original_shop_catalog_empty");
    return result;
}
OriginalShop::OriginalShop(OriginalShopSetup setup, OriginalShopCatalog catalog,
    std::shared_ptr<const OriginalCardCombinations> combinations, OriginalShopWallet wallet,
    std::function<std::uint32_t(std::uint32_t)> random)
    : setup_(setup),catalog_(std::move(catalog)),combinations_(std::move(combinations)),wallet_(std::move(wallet)),random_(std::move(random)) {
    if (!combinations_ || !random_ || catalog_.offers.empty()) throw CodecError("original_shop_dependencies_missing");
    if (setup_.owner >= 8) throw CodecError("original_shop_owner_invalid");
    if (wallet_.tickets > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
        wallet_.account_reserve > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("original_shop_wallet_invalid");
    if (setup_.refresh_gold_cost && *setup_.refresh_gold_cost > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("original_shop_refresh_price_invalid");
    validate_original_inventory(wallet_.inventory);
    std::set<std::int16_t> unique;
    for (const auto card : catalog_.offers) {
        if (card < 0 || !catalog_.prices.contains(card) || catalog_.prices.at(card) < 0 || !catalog_.counts.contains(card) ||
            catalog_.counts.at(card) < 1 || !unique.insert(card).second)
            throw CodecError("original_shop_offer_invalid");
    }
    stock_ = select_stock();
}
std::array<OriginalCardSlot,12> OriginalShop::select_stock() const {
    std::array<OriginalCardSlot,12> result;
    result.fill({-1,0,{0,255}});
    auto remaining = catalog_.offers;
    for (auto& slot : result) {
        if (remaining.empty()) break;
        const auto selected = random_(static_cast<std::uint32_t>(remaining.size()));
        if (selected >= remaining.size()) throw CodecError("original_shop_random_out_of_range");
        slot.id = remaining[selected]; slot.count = catalog_.counts.at(slot.id);
        remaining.erase(remaining.begin()+static_cast<std::ptrdiff_t>(selected));
    }
    return result;
}
Bytes OriginalShop::open_message() const {
    if (closed_) throw CodecError("original_shop_already_closed");
    return encode_original_shop_stock({setup_.instance,stock_,false});
}
}
