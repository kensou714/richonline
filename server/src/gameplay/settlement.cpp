#include "richonline_settlement.hpp"

#include <array>
#include <algorithm>
#include <functional>

namespace richnet {
GameSettlementPolicy richonline_boss_settlement_policy(const RichonlineBossStage& stage,
    const std::array<std::uint32_t,21>& levels,const RichonlineBossSettlementRules& rules) {
    if(rules.provenance.empty() || rules.provenance.size()>800 || rules.provenance.find('\0')!=std::string::npos ||
        stage.map_name.empty() || stage.map_name.size()>128 || stage.map_name.find('\0')!=std::string::npos)
        throw CodecError("richonline_settlement_policy_provenance_invalid");
    if(levels.front()!=0 || levels.back()>2147483647U ||
        std::adjacent_find(levels.begin(),levels.end(),std::greater_equal<>())!=levels.end())
        throw CodecError("richonline_settlement_policy_levels_invalid");
    const auto returned_pledge=rules.return_winning_pledge?stage.pawn_gold:0U;
    auto win=[&](const RichonlineStageReward& resource,std::uint32_t bonus) {
        if(resource.experience>32767 || resource.gold>2147483647U || returned_pledge>2147483647U-resource.gold || bonus>2147483647U)
            throw CodecError("richonline_settlement_policy_reward_out_of_range");
        if(resource.item_count>8 || resource.item_ids.size()!=resource.item_count)
            throw CodecError("richonline_settlement_policy_item_specification_invalid");
        std::optional<GameSettlementItemReward> items;
        if(resource.item_count!=0)items=GameSettlementItemReward{resource.item_count,resource.item_ids};
        return GameSettlementReward{resource.experience,resource.gold+returned_pledge,bonus,std::move(items)};
    };
    for(const auto& reward:{rules.loss,rules.draw}) {
        if(reward.experience>32767 || reward.gold_return>2147483647U || reward.bonus_gold>2147483647U)
            throw CodecError("richonline_settlement_policy_reward_out_of_range");
        if(reward.items && (reward.items->resource_count==0 || reward.items->resource_count>8 ||
            reward.items->resource_ids.size()!=reward.items->resource_count))
            throw CodecError("richonline_settlement_policy_item_specification_invalid");
    }
    return {"NEW BossWar "+stage.map_name+"; "+rules.provenance,win(stage.first_reward,rules.first_win_bonus),
        win(stage.repeat_reward,rules.repeat_win_bonus),rules.loss,rules.draw,levels,returned_pledge};
}

Frame richonline_lobby_game_finished(std::uint32_t room_id) {
    // The wire reader takes DWORD, but the callback packs the room into a
    // signed short; accepting a larger key targets the wrong room in6AC070.
    if(room_id>32767) throw CodecError("richonline_settlement_room_id_out_of_range");
    Bytes payload;append_le(payload,room_id,4);
    return {58,std::move(payload)};
}

std::vector<Bytes> plan_richonline_settlement(std::uint16_t game_id,
    std::span<const std::int8_t> bankrupt_slots,
    std::span<const RichonlineSettledActor> actors,bool show_text_270) {
    if(actors.empty() || actors.size()>8) throw CodecError("richonline_settlement_actor_count_invalid");
    std::array<bool,8> bankrupt{};
    std::array<bool,8> recorded{};
    std::vector<Bytes> result;
    for(const auto slot:bankrupt_slots) {
        if(slot<0 || slot>=8 || bankrupt[static_cast<std::size_t>(slot)])
            throw CodecError("richonline_settlement_bankrupt_slots_invalid");
        bankrupt[static_cast<std::size_t>(slot)]=true;
        result.push_back(richonline_eliminate_actor(game_id,slot));
    }
    for(const auto& actor:actors) {
        if(actor.slot<0 || actor.slot>=8 || recorded[static_cast<std::size_t>(actor.slot)])
            throw CodecError("richonline_settlement_actor_slot_invalid");
        recorded[static_cast<std::size_t>(actor.slot)]=true;
        switch(actor.outcome) {
        case GameOutcome::win:case GameOutcome::loss:case GameOutcome::draw:break;
        default:throw CodecError("richonline_settlement_outcome_invalid");
        }
        if(actor.outcome==GameOutcome::win && (actor.escaped || bankrupt[static_cast<std::size_t>(actor.slot)]))
            throw CodecError("richonline_settlement_winner_invalid");
        if(actor.outcome==GameOutcome::win)
            result.push_back(richonline_victory_notice(game_id,actor.slot));
        const auto& persisted=actor.persisted;
        if(persisted.reward.experience>32767 || persisted.reward.gold_return>2147483647U ||
            persisted.reward.bonus_gold>2147483647U || persisted.level_before>20 || persisted.level_after>20 ||
            persisted.level_after<persisted.level_before)
            throw CodecError("richonline_settlement_result_out_of_range");
        result.push_back(encode_richonline_game_result({game_id,actor.slot,actor.rank_image_index,
            static_cast<std::int16_t>(persisted.reward.experience),persisted.reward.gold_return,persisted.reward.bonus_gold,
            static_cast<std::uint8_t>(actor.outcome==GameOutcome::win),static_cast<std::uint8_t>(actor.escaped),
            actor.opaque_18,static_cast<std::uint8_t>(persisted.level_after>persisted.level_before)}));
    }
    result.push_back(richonline_show_game_results(game_id,show_text_270));
    return result;
}
}
