#include "original_shop.hpp"
#include <limits>
#include <type_traits>

namespace richnet {
OriginalShopResult OriginalShop::close(std::optional<std::string> reason) {
    if (closed_) return {{},true,std::move(reason)};
    auto packet = encode_original_shop_choice(setup_.instance,-1);
    closed_ = true;
    return {{std::move(packet)},true,std::move(reason)};
}
OriginalShopResult OriginalShop::poll(OriginalShopClock::time_point now) {
    if (!closed_ && now >= deadline()) return close();
    return {{},closed_,{}};
}
OriginalShopResult OriginalShop::handle(const OriginalShopRequest& request, OriginalShopClock::time_point now) {
    return std::visit([&](const auto& value) -> OriginalShopResult {
        if (value.context != setup_.context) throw CodecError("original_shop_context_mismatch");
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T,OriginalShopChoice>) {
            if (value.index == -1) return close();
        }
        if (closed_) throw CodecError("original_shop_already_closed");
        if (now >= deadline()) return close("original_shop_deadline_reached");
        if constexpr (std::is_same_v<T,OriginalShopChoice>) return buy(value.index);
        else if constexpr (std::is_same_v<T,OriginalShopSale>) return sell(value.slot);
        else if constexpr (std::is_same_v<T,OriginalShopRefresh>) return refresh();
        else if constexpr (std::is_same_v<T,OriginalCardDiscard>) {
            if (value.slot < 0 || value.slot >= 8) throw CodecError("original_shop_inventory_slot_invalid");
            const auto index = static_cast<std::uint8_t>(value.slot);
            auto changed = discard_original_card(wallet_.inventory,index);
            auto packet = encode_original_card_discard(setup_.instance,index,setup_.owner);
            wallet_.inventory = std::move(changed.inventory);
            return {{std::move(packet)},false,{}};
        } else { static_assert(!sizeof(T),"unhandled original shop request"); }
    },request);
}
OriginalShopResult OriginalShop::buy(std::int8_t index) {
    if (index < 0 || index >= 12) throw CodecError("original_shop_index_invalid");
    auto& offer = stock_[static_cast<std::uint8_t>(index)];
    if (offer.id == -1) return close("original_shop_offer_empty");
    const auto price = static_cast<std::uint32_t>(catalog_.prices.at(offer.id));
    if (wallet_.tickets < price) return close("original_shop_insufficient_tickets");
    auto changed = add_original_card(wallet_.inventory,offer.id,offer.count);
    if (!changed.slot) return close("original_shop_inventory_full");
    auto combined = combine_original_cards(changed.inventory,*combinations_,catalog_.combination_outputs);
    auto packet = encode_original_shop_choice(setup_.instance,index);
    wallet_.inventory = std::move(combined.inventory); wallet_.tickets -= price;
    offer.id = -1; offer.count = 0;
    return {{std::move(packet)},false,{}};
}
OriginalShopResult OriginalShop::sell(std::int8_t slot) {
    if (slot < 0 || slot >= 8) throw CodecError("original_shop_inventory_slot_invalid");
    const auto index = static_cast<std::uint8_t>(slot);
    const auto card = wallet_.inventory[index].id;
    if (card == -1) return close("original_shop_sale_slot_empty");
    const auto found = catalog_.prices.find(card);
    if (found == catalog_.prices.end() || found->second < 0) throw CodecError("original_shop_sale_price_unknown");
    const auto refund = static_cast<std::uint32_t>(found->second >> 1);
    if (refund > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-wallet_.tickets)
        return close("original_shop_ticket_overflow");
    auto changed = discard_original_card(wallet_.inventory,index);
    auto packet = encode_original_shop_sale(setup_.instance,slot);
    wallet_.inventory = std::move(changed.inventory); wallet_.tickets += refund;
    return {{std::move(packet)},false,{}};
}
OriginalShopResult OriginalShop::refresh() {
    if (!setup_.refresh_gold_cost) return close("original_shop_refresh_price_unrecovered");
    if (refreshes_ >= 5) return close("original_shop_refresh_limit");
    const auto price = *setup_.refresh_gold_cost;
    if (wallet_.account_reserve < price) return close("original_shop_insufficient_gold");
    auto stock = select_stock();
    auto packet = encode_original_shop_stock({setup_.instance,stock,true});
    wallet_.account_reserve -= price; stock_ = std::move(stock); ++refreshes_;
    return {{std::move(packet)},false,{},price};
}
}
