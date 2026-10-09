#include "original_boss_match.hpp"
#include "original_turn_wire.hpp"
#include <algorithm>

namespace richnet {
OriginalBossMatch::OriginalBossMatch(OriginalBossBoard board, OriginalBossMatchResources resources,
    OriginalBossMatchPolicy policy)
    : startup_(std::move(board.startup)),map_(std::make_shared<OriginalMapResources>(std::move(board.map))),
      resources_(std::move(resources)),policy_(std::move(policy)),
      properties_(startup_.init.gmsv_id,map_,resources_.buildings),research_(resources_.research),
      context_(startup_.snapshot.context) {
    validate_original_startup(startup_);
    if (startup_.init.players.size() != 2 || startup_.init.local_slot != 0 ||
        startup_.init.players[0].lobby_user_id < 0 || startup_.init.players[1].lobby_user_id != -1)
        throw CodecError("original_boss_match_requires_human_and_boss");
    if (!resources_.combinations || !policy_.random || !policy_.clock)
        throw CodecError("original_boss_match_dependencies_required");
    if (board.settings.attack.attempts != 0) throw CodecError("original_boss_attack_strategy_unavailable");
    if (board.settings.human_initial_cards.size() > 4) throw CodecError("original_boss_initial_cards_exceed_wire_capacity");
    for (std::uint8_t slot = 0; slot < 2; ++slot) {
        const auto& player = startup_.init.players[slot];
        actors_[slot] = {startup_.snapshot.per_player[slot],make_original_inventory(),player.skills,
            false,slot == 1,false,false,false};
        movements_.emplace_back(map_,OriginalMovementSetup{startup_.init.gmsv_id,action_context(),
            player.initial_tile,player.direction,policy_.dice_counts[slot],policy_.wire.movement},policy_.random);
        movements_.back().set_effects({{{},false,{},{}},{slot,true,{},{}},slot == 0});
    }
    for (const auto card : board.settings.human_initial_cards) {
        if (!resources_.shop.prices.contains(card)) throw CodecError("original_boss_initial_card_unknown");
        actors_[0].inventory = add_original_card(actors_[0].inventory,card,1).inventory;
    }
}
std::vector<Bytes> OriginalBossMatch::start() {
    if (phase_ == OriginalBossMatchPhase::closed) throw CodecError("original_boss_match_closed");
    if (phase_ != OriginalBossMatchPhase::loading) return {};
    std::vector<Bytes> replies;
    for (std::uint8_t slot = 0; slot < 2; ++slot) {
        std::array<OriginalCardSlot,4> cards;
        std::copy_n(actors_[slot].inventory.begin(),4,cards.begin());
        replies.push_back(encode_original_initial_cards({startup_.init.gmsv_id,slot,cards,policy_.wire.initial_cards_suffix}));
    }
    begin_turn(replies);
    return replies;
}
void OriginalBossMatch::begin_turn(std::vector<Bytes>& replies) {
    OriginalResearchInventories inventories;
    inventories.fill(make_original_inventory());
    for (std::uint8_t slot = 0; slot < 2; ++slot) inventories[slot] = actors_[slot].inventory;
    auto advanced = research_.advance(current_,properties_.records(),
        {inventories,*resources_.combinations,resources_.shop.combination_outputs});
    actors_[current_].inventory = std::move(advanced.inventories[current_]);
    ++context_;
    auto& movement = movements_[current_];
    movement.begin_turn(action_context());
    replies.push_back(encode_original_turn_start({startup_.init.gmsv_id,current_,1,policy_.wire.turn_suffix}));
    replies.push_back(encode_original_boss_turn_resume({startup_.init.gmsv_id,policy_.wire.resume_suffix}));
    phase_ = OriginalBossMatchPhase::dice;
    if (current_ == 1) {
        auto roll = movement.handle(OriginalRollRequest{action_context(),0});
        replies.insert(replies.end(),roll.messages.begin(),roll.messages.end());
        phase_ = OriginalBossMatchPhase::movement;
    }
    if (policy_.log) policy_.log("original_boss_turn_started instance="+std::to_string(startup_.init.gmsv_id)+
        " context="+std::to_string(context_)+" actor="+std::to_string(current_));
}
void OriginalBossMatch::complete_landing(std::vector<Bytes>& replies) {
    auto& movement = movements_[current_];
    if (movement.wait_for_direction()) {
        phase_ = OriginalBossMatchPhase::direction;
        return;
    }
    movement.finish_landing();
    current_ = static_cast<std::uint8_t>(1-current_);
    begin_turn(replies);
}
std::vector<Bytes> OriginalBossMatch::poll() {
    if (phase_ != OriginalBossMatchPhase::shop) return {};
    std::vector<Bytes> replies;
    shop_result(shop_->poll(policy_.clock()),replies);
    return replies;
}
void OriginalBossMatch::close() noexcept {
    phase_ = OriginalBossMatchPhase::closed;
    shop_.reset();
}
OriginalGamePlan original_boss_match_plan(std::shared_ptr<OriginalBossMatch> match) {
    if (!match) throw CodecError("original_boss_match_required");
    return {match->startup(),[match] { return match->start(); },
        [match](View plain) { return match->action(plain); },[match] { match->close(); },
        [match] { return match->poll(); },[match] { return match->closed_shop_context(); },
        [match](View plain) { return match->expired_shop_action(plain); }};
}
}
