#include "original_card_reward.hpp"
#include "original_shop_wire.hpp"

namespace richnet {
OriginalCardReward grant_original_card(const OriginalInventory& inventory,
    OriginalCardRewardRequest request, const OriginalCardCombinations& recipes,
    std::span<const std::int16_t> allowed_outputs) {
    auto message = encode_original_card_grant(request.instance,request.card);
    auto added = add_original_card(inventory,request.card,1);
    if (!added.slot) return {inventory,false,{},std::move(message)};
    auto combined = combine_original_cards(added.inventory,recipes,allowed_outputs);
    return {std::move(combined.inventory),true,std::move(combined.applied),std::move(message)};
}
}
