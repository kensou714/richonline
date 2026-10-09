#include "original_boss_match.hpp"
#include "original_card_reward.hpp"
#include <limits>

namespace richnet {
void OriginalBossMatch::grant_card(std::int16_t card, std::vector<Bytes>& replies) {
    auto grant = grant_original_card(actors_[current_].inventory,{startup_.init.gmsv_id,card},
        *resources_.combinations,resources_.shop.combination_outputs);
    actors_[current_].inventory = std::move(grant.inventory);
    replies.push_back(std::move(grant.message));
}
void OriginalBossMatch::land(const OriginalMovementEvent& event, std::vector<Bytes>& replies) {
    if (event.kind != OriginalStopKind::landing) throw CodecError("original_boss_match_bomb_effect_unimplemented");
    if (event.cell.tile == movements_[1-current_].state().tile)
        throw CodecError("original_boss_match_encounter_unimplemented");
    switch (event.cell.type) {
    case 5:
    case 6:
    case 7:
        if (current_ == 0) {
            const std::uint32_t reward = event.cell.type == 5 ? 80U : event.cell.type == 6 ? 50U : 30U;
            auto& tickets = actors_[current_].funds.tickets;
            if (tickets > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-reward)
                throw CodecError("original_boss_match_ticket_overflow");
            tickets += reward;
        }
        break;
    case 8:
        if (current_ == 0) {
            std::uint64_t total = 0;
            for (const auto& card : map_->card_weights) total += card.weight;
            if (total == 0 || total > std::numeric_limits<std::uint32_t>::max())
                throw CodecError("original_boss_match_card_pool_invalid");
            auto pick = policy_.random(static_cast<std::uint32_t>(total));
            if (pick >= total) throw CodecError("original_boss_match_random_out_of_range");
            for (const auto& card : map_->card_weights) {
                if (pick < card.weight) { grant_card(card.card,replies); break; }
                pick -= card.weight;
            }
        }
        break;
    case 41:
    case 42:
        if (current_ == 0) grant_card(event.cell.type == 41 ? 1044 : 1046,replies);
        break;
    case 10: {
        closed_shop_.reset();
        shop_.emplace(OriginalShopSetup{startup_.init.gmsv_id,action_context(),current_,policy_.clock(),{}},
            resources_.shop,resources_.combinations,
            OriginalShopWallet{actors_[current_].inventory,actors_[current_].funds.tickets,0},policy_.random);
        phase_ = OriginalBossMatchPhase::shop;
        replies.push_back(shop_->open_message());
        if (current_ == 1) shop_result(shop_->handle(OriginalShopChoice{action_context(),-1,policy_.wire.boss_choice_opaque},
            policy_.clock()),replies);
        return;
    }
    case 33:
    case 34:
    case 35:
    case 36:
        break;
    default:
        throw CodecError("original_boss_match_tile_unimplemented type="+std::to_string(event.cell.type)+
            " tile="+std::to_string(event.cell.tile)+" context="+std::to_string(context_));
    }
    if (event.cell.property_id >= 0) begin_property(replies);
    else complete_landing(replies);
}
}
