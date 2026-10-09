#include "original_boss_match.hpp"
#include <algorithm>

namespace richnet {
std::optional<std::uint16_t> OriginalBossMatch::closed_shop_context() const {
    if (!closed_shop_ || phase_ == OriginalBossMatchPhase::closed ||
        context_-closed_shop_->context > 1 || policy_.clock() >= closed_shop_->expires) return {};
    return static_cast<std::uint16_t>(closed_shop_->context & 0xffffU);
}
bool OriginalBossMatch::expired_shop_action(View plain) const {
    if (plain.size() < 4) return false;
    const auto closed = closed_shop_context();
    if (!closed || read_le(plain.subspan(2,2)) != *closed) return false;
    switch (read_le(plain.first(2))) {
    case 48: case 49: case 50: case 53:
        static_cast<void>(parse_original_shop_request(plain));
        return true;
    default: return false;
    }
}
std::vector<Bytes> OriginalBossMatch::action(View plain) {
    if (phase_ == OriginalBossMatchPhase::closed) throw CodecError("original_boss_match_closed");
    if (phase_ == OriginalBossMatchPhase::loading) throw CodecError("original_boss_match_not_ready");
    if (plain.size() < 4) throw CodecError("original_boss_match_action_truncated");
    const auto opcode = read_le(plain.first(2));
    if (expired_shop_action(plain)) return {};
    if (read_le(plain.subspan(2,2)) != action_context()) throw CodecError("original_boss_match_context_mismatch");
    std::vector<Bytes> replies;
    switch (opcode) {
    case 16:
    case 20: {
        if (current_ != 0 || phase_ != OriginalBossMatchPhase::dice)
            throw CodecError("original_boss_match_human_dice_not_pending");
        auto result = movements_[current_].handle(parse_original_movement_request(plain));
        replies = std::move(result.messages);
        if (opcode == 16) phase_ = OriginalBossMatchPhase::movement;
        return replies;
    }
    case 17:
    case 18: {
        if (phase_ != OriginalBossMatchPhase::movement) throw CodecError("original_boss_match_movement_not_pending");
        auto result = movements_[current_].handle(parse_original_movement_request(plain));
        replies = std::move(result.messages);
        if (!result.event) throw CodecError("original_boss_match_landing_missing");
        land(*result.event,replies);
        return replies;
    }
    case 52: {
        if (current_ != 0 || phase_ != OriginalBossMatchPhase::direction)
            throw CodecError("original_boss_match_direction_not_pending");
        auto result = movements_[current_].handle(parse_original_movement_request(plain));
        replies = std::move(result.messages);
        complete_landing(replies);
        return replies;
    }
    case 48:
    case 49:
    case 53:
        if (current_ != 0 || phase_ != OriginalBossMatchPhase::shop)
            throw CodecError("original_boss_match_shop_not_pending");
        shop_result(shop_->handle(parse_original_shop_request(plain),policy_.clock()),replies);
        return replies;
    case 50: {
        if (current_ != 0 || (phase_ != OriginalBossMatchPhase::dice && phase_ != OriginalBossMatchPhase::shop))
            throw CodecError("original_boss_match_discard_unavailable");
        const auto request = parse_original_shop_request(plain);
        if (phase_ == OriginalBossMatchPhase::shop) {
            shop_result(shop_->handle(request,policy_.clock()),replies);
        } else {
            const auto& discard = std::get<OriginalCardDiscard>(request);
            if (discard.slot < 0 || discard.slot >= 8) throw CodecError("original_boss_match_discard_slot_invalid");
            const auto slot = static_cast<std::uint8_t>(discard.slot);
            auto changed = discard_original_card(actors_[0].inventory,slot);
            replies.push_back(encode_original_card_discard(startup_.init.gmsv_id,slot,0));
            actors_[0].inventory = std::move(changed.inventory);
        }
        return replies;
    }
    case 32:
    case 55:
    case 56:
    case 57:
        if (current_ != 0 || phase_ != OriginalBossMatchPhase::property)
            throw CodecError("original_boss_match_property_not_pending");
        property_result(parse_original_property_request(plain),replies);
        return replies;
    default:
        throw CodecError("original_boss_match_action_unimplemented opcode="+std::to_string(opcode)+
            " context="+std::to_string(context_)+" actor="+std::to_string(current_));
    }
}
void OriginalBossMatch::shop_result(OriginalShopResult result, std::vector<Bytes>& replies) {
    actors_[current_].inventory = shop_->wallet().inventory;
    actors_[current_].funds.tickets = shop_->wallet().tickets;
    replies.insert(replies.end(),result.messages.begin(),result.messages.end());
    if (result.rejection && policy_.log) policy_.log("original_boss_shop_rejected instance="+
        std::to_string(startup_.init.gmsv_id)+" context="+std::to_string(context_)+" reason="+*result.rejection);
    if (!result.closed) return;
    if (current_ == 0) closed_shop_ = ClosedShop{context_,policy_.clock()+std::chrono::seconds(10)};
    shop_.reset();
    const auto tile = movements_[current_].state().tile;
    const auto road = std::find_if(map_->roads.begin(),map_->roads.end(),[tile](const auto& cell) { return cell.tile == tile; });
    if (road->property_id >= 0) begin_property(replies);
    else complete_landing(replies);
}
}
