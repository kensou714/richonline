#include "richonline_npc_aura.hpp"
#include "original_game_values.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace richnet {
namespace {
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void validate(const RichonlineNpcAuraRules& rules) {
    if(rules.amount<0 || rules.radius<0)
        throw CodecError("richonline_npc_aura_rules_invalid");
}
std::int32_t scaled_amount(const RichonlineNpcAuraRules& rules,const RichonlineNpcAuraContext& context) {
    if(!context.effect) throw CodecError("richonline_npc_aura_effect_unknown");
    const auto& effect=*context.effect;
    if(effect.strength1740<=0) return rules.amount;
    if(!std::isfinite(effect.multiplier1744) || effect.multiplier1744<0.0F)
        throw CodecError("richonline_npc_aura_multiplier_invalid");
    // x87 stores the integer base as float, multiplies the two float operands
    // without a float product store, then __ftol2 truncates. A double product
    // preserves their exact product; rounding it to float changes some results.
    const auto value=static_cast<double>(static_cast<float>(rules.amount))*
        static_cast<double>(effect.multiplier1744);
    const auto truncated=std::trunc(value);
    if(truncated>static_cast<double>(maximum))
        throw CodecError("richonline_npc_aura_amount_overflow");
    return static_cast<std::int32_t>(truncated);
}
bool eligible(const RichonlineRawActorState& raw) {
    if(!raw.hospital1494 || !raw.jail1495 || !raw.kidnapped1497)
        throw CodecError("richonline_npc_aura_target_unknown");
    return *raw.hospital1494==-1 && *raw.jail1495==-1 && *raw.kidnapped1497==-1;
}
}
RichonlineNpcAuraRules RichonlineNpcAuraRules::load(const std::filesystem::path& root) {
    const auto values=load_original_game_values(root/"Data/GValue.kpd");
    RichonlineNpcAuraRules rules{values.require(15),values.require(24)};
    validate(rules);return rules;
}
RichonlineNpcAuraPlan plan_richonline_npc_aura(const RichonlineRoadTopology& topology,
    const RichonlineNpcAuraRules& rules,const RichonlineNpcAuraContext& context,
    std::span<const RichonlineNpcAuraActor> actors) {
    validate(rules);
    if(context.mode!=3 || actors.empty() || actors.size()>8 || !topology.width() || !topology.height())
        throw CodecError("richonline_npc_aura_context_invalid");
    std::array<bool,8> seen{};
    const RichonlineNpcAuraActor* source=nullptr;
    for(const auto& target:actors) {
        if(target.slot>=seen.size() || seen[target.slot])
            throw CodecError("richonline_npc_aura_actor_invalid");
        seen[target.slot]=true;
        if(target.slot==context.active_actor) source=&target;
    }
    if(!source || !source->active || context.boss_slot>=seen.size() || !seen[context.boss_slot])
        throw CodecError("richonline_npc_aura_source_invalid");
    if(context.possession!=4 && context.possession!=6) return {0,{},{}};
    const auto amount=scaled_amount(rules,context);
    const auto width=static_cast<std::int64_t>(topology.width());
    const auto height=static_cast<std::int64_t>(topology.height());
    const auto valid_position=[width,height](std::int16_t position) {
        return position>=0 && static_cast<std::int64_t>(position)<width*height;
    };
    if(!valid_position(source->position)) throw CodecError("richonline_npc_aura_position_invalid");
    const auto x=source->position%width,y=source->position/width;
    const auto left=std::max<std::int64_t>(0,x-rules.radius),right=std::min(width-1,x+rules.radius);
    const auto top=std::max<std::int64_t>(0,y-rules.radius),bottom=std::min(height-1,y+rules.radius);
    std::vector<const RichonlineNpcAuraActor*> targets;
    for(const auto& target:actors) {
        if(!target.active || target.slot==context.boss_slot) continue;
        if(!valid_position(target.position)) throw CodecError("richonline_npc_aura_position_invalid");
        const auto tx=target.position%width,ty=target.position/width;
        if(tx<left || tx>right || ty<top || ty>bottom || !eligible(target.raw)) continue;
        targets.push_back(&target);
    }
    // Match the client's row/column/actor iteration even for unsorted input.
    std::sort(targets.begin(),targets.end(),[](const auto* a,const auto* b) {
        return a->position==b->position ? a->slot<b->slot : a->position<b->position;
    });
    RichonlineNpcAuraPlan result{amount,{},{}};
    result.updates.reserve(targets.size());result.bankrupt_actors.reserve(targets.size());
    for(const auto* target:targets) {
        auto after=target->funds.funds;
        if(after.cash>maximum || (after.deposit && *after.deposit>maximum))
            throw CodecError("richonline_npc_aura_balance_invalid");
        const auto value=static_cast<std::uint32_t>(amount);
        if(context.possession==4) {
            if(value>maximum-after.cash) throw CodecError("richonline_npc_aura_cash_overflow");
            after.cash+=value;
        } else {
            if(!after.deposit) throw CodecError("richonline_npc_aura_deposit_unknown");
            const auto cash=std::min(value,after.cash);
            after.cash-=cash;
            const auto deficit=value-cash;
            *after.deposit-=std::min(deficit,*after.deposit);
            // 606E -> 6803C0 calls 605545 -> 63F620 (cash1504 only).
            // Cash reaching zero marks bankruptcy even with surviving deposit.
            if(after.cash==0) result.bankrupt_actors.push_back(target->slot);
        }
        result.updates.push_back({target->slot,target->funds,after});
    }
    return result;
}
} // namespace richnet
