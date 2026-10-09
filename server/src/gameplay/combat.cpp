#include "richonline_combat.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <charconv>
#include <map>
#include <set>

namespace richnet {
namespace {
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void checked_mines(const RichonlineMineSnapshot& state) {
    for (std::size_t i=0;i<state.mines.size();++i) {
        const auto& mine=state.mines[i];
        if (mine.position<0 || mine.owner < -1 || mine.owner>=8 || mine.remaining_days>3 ||
            (mine.kind!=RichonlineMineKind::normal && mine.kind!=RichonlineMineKind::super))
            throw CodecError("richonline_combat_mine_invalid");
        for (std::size_t j=0;j<i;++j)
            if (state.mines[j].position==mine.position) throw CodecError("richonline_combat_mine_duplicate");
    }
}
void next_revision(RichonlineMineSnapshot& state) {
    if (state.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_combat_revision_overflow");
    ++state.revision;
}
std::uint32_t rounded_damage(double amount) {
    if (!std::isfinite(amount) || amount<0 || amount+0.5>maximum)
        throw CodecError("richonline_combat_damage_overflow");
    return static_cast<std::uint32_t>(amount+0.5);
}
std::string_view trim(std::string_view text) {
    const auto first=text.find_first_not_of(" \t\r");
    return first==text.npos?std::string_view{}:text.substr(first,text.find_last_not_of(" \t\r")-first+1);
}
std::map<std::int32_t,std::uint32_t> resource_values(std::string_view text,std::string_view section,std::string_view key) {
    if (text.size()>8U*1024U*1024U || text.find('\0')!=text.npos) throw CodecError("richonline_combat_resource_invalid");
    std::map<std::int32_t,std::uint32_t> result;
    bool active=false; std::optional<std::int32_t> id; std::optional<std::uint32_t> value;
    const auto save=[&] {
        if (active && value && (!id || !result.emplace(*id,*value).second))
            throw CodecError("richonline_combat_resource_duplicate");
    };
    const auto number=[](std::string_view s) {
        s=trim(s); std::int32_t v=0; const auto parsed=std::from_chars(s.data(),s.data()+s.size(),v);
        if (s.empty() || parsed.ec!=std::errc{} || parsed.ptr!=s.data()+s.size() || v<0)
            throw CodecError("richonline_combat_resource_number_invalid");
        return v;
    };
    while (!text.empty()) {
        const auto newline=text.find('\n'); const auto line=trim(text.substr(0,newline));
        if (newline==text.npos) text={}; else text.remove_prefix(newline+1);
        if (line.empty() || line.starts_with("//") || line.front()==';') continue;
        if (line.front()=='[') { save(); active=line==section; id.reset();value.reset();continue; }
        if (!active) continue;
        const auto equal=line.find('='); if (equal==line.npos) throw CodecError("richonline_combat_resource_invalid");
        const auto name=trim(line.substr(0,equal));
        if (name=="indx") { if(id) throw CodecError("richonline_combat_resource_duplicate"); id=number(line.substr(equal+1)); }
        else if (name==key) { if(value) throw CodecError("richonline_combat_resource_duplicate"); value=static_cast<std::uint32_t>(number(line.substr(equal+1))); }
    }
    save(); return result;
}
}
RichonlineCombatResources RichonlineCombatResources::parse(std::string_view props,std::string_view npcs,std::string_view values) {
    const auto cards=resource_values(props,"[PROP]","hurt");
    const auto dynamic=resource_values(npcs,"[NPC]","hurt");
    const auto constants=resource_values(values,"[ITEM]","value");
    const auto required=[](const auto& table,std::int32_t id) {
        const auto it=table.find(id);
        if (it==table.end() || it->second==0) throw CodecError("richonline_combat_resource_missing");
        return it->second;
    };
    const auto small=[&](std::int32_t id) {
        const auto value=required(constants,id);
        if (value>127) throw CodecError("richonline_combat_resource_range");
        return static_cast<std::uint8_t>(value);
    };
    return {required(dynamic,12),required(dynamic,13),required(dynamic,27),required(cards,1046),required(cards,1063),
        small(19),small(20),small(21),small(22),small(23)};
}
std::uint32_t RichonlineCombatResources::base_damage(RichonlineCombatEffect effect) const {
    switch(effect) {
    case RichonlineCombatEffect::mine:return mine_damage;
    case RichonlineCombatEffect::timed_bomb:return timed_bomb_damage;
    case RichonlineCombatEffect::missile:return missile_damage;
    case RichonlineCombatEffect::nuclear:case RichonlineCombatEffect::safe_nuclear:return nuclear_damage;
    }
    throw CodecError("richonline_combat_effect_invalid");
}
std::uint32_t calculate_richonline_combat_damage(std::uint32_t base,
    const RichonlineActorStatus& attacker,const RichonlineActorStatus& defender,
    const RichonlineCombatModifiers& attack,const RichonlineCombatModifiers& defense,
    bool attacker_enabled,std::int32_t flat_attack,std::int32_t flat_defense) {
    if (!base || base>maximum || flat_attack<0 || flat_defense<0)
        throw CodecError("richonline_combat_damage_terms_invalid");
    float factor=1.0F;
    const auto multiply=[&](float v) {
        if (!std::isfinite(v) || v<0) throw CodecError("richonline_combat_modifier_invalid");
        factor*=v; // NEW stores to float after each x87 term.
        if (!std::isfinite(factor)) throw CodecError("richonline_combat_damage_overflow");
    };
    const auto check=[](const RichonlineCombatModifiers& modifiers) {
        if (!std::isfinite(modifiers.possession_amplification) || modifiers.possession_amplification<0 ||
            modifiers.possession_amplification>0.5F) throw CodecError("richonline_combat_modifier_invalid");
    };
    check(attack);check(defense);
    if (attacker_enabled) {
        if (attacker.possession==3) multiply(1.5F+attack.possession_amplification);
        else if (attacker.possession==2) multiply(0.5F-attack.possession_amplification);
        multiply(attack.building_multiplier);
        if (attacker.attack_turns) multiply(attacker.attack_multiplier);
        multiply(attack.secondary_status_multiplier);
        multiply(1.0F+static_cast<float>(attack.equipment_percentage)/100.0F);
        multiply(attack.special_multiplier);
    }
    if (defender.possession==0) multiply(0.5F-defense.possession_amplification);
    else if (defender.possession==1) multiply(1.5F+defense.possession_amplification);
    multiply(defense.building_multiplier);
    if (defender.damage_turns) multiply(defender.damage_multiplier);
    multiply(defense.secondary_status_multiplier);
    multiply(1.0F-static_cast<float>(defense.equipment_percentage)/100.0F);
    multiply(defense.special_multiplier);
    const auto rounded=rounded_damage(static_cast<double>(static_cast<float>(base))*factor);
    const auto amount=static_cast<std::int64_t>(rounded)+(attacker_enabled?flat_attack:0)-flat_defense;
    if (amount>maximum) throw CodecError("richonline_combat_damage_overflow");
    return static_cast<std::uint32_t>(std::max<std::int64_t>(1,amount));
}
Bytes encode_richonline_mine_day401e(std::uint16_t game_id) {
    Bytes out; append_le(out,0x401e,2); append_le(out,game_id,2); return out;
}
Bytes encode_richonline_mine_explosion4017(std::uint16_t game_id,std::int16_t position) {
    if (position<0) throw CodecError("richonline_combat_position_invalid");
    Bytes out; append_le(out,0x4017,2); append_le(out,game_id,2);
    append_le(out,static_cast<std::uint16_t>(position),2); return out;
}
RichonlineMineDayPlan plan_richonline_mine_day(const RichonlineMineSnapshot& before,
    std::uint64_t day,std::uint16_t game_id,bool anchor) {
    checked_mines(before);
    if (!anchor) throw CodecError("richonline_combat_day_requires_round_anchor");
    if (before.last_day && day<*before.last_day) throw CodecError("richonline_combat_stale_day");
    RichonlineMineDayPlan out{before,before,{},{}};
    if (before.last_day && day==*before.last_day) return out;
    if (before.last_day && day-*before.last_day!=1) throw CodecError("richonline_combat_day_gap");
    out.after.last_day=day;
    next_revision(out.after);
    out.packets.push_back(encode_richonline_mine_day401e(game_id));
    for (auto& mine:out.after.mines) {
        if (mine.remaining_days>0) --mine.remaining_days;
        if (mine.remaining_days==0) {
            out.expired.push_back(mine);
            out.packets.push_back(encode_richonline_mine_explosion4017(game_id,mine.position));
        }
    }
    std::erase_if(out.after.mines,[](const auto& mine) { return mine.remaining_days==0; });
    return out;
}
RichonlineMineSnapshot plan_richonline_mine_placement(const RichonlineMineSnapshot& before,
    std::int16_t position,std::int8_t owner,bool legal) {
    checked_mines(before);
    if (!legal || position<0 || owner<0 || owner>=8) throw CodecError("richonline_combat_mine_target_invalid");
    if (std::ranges::any_of(before.mines,[&](const auto& mine) { return mine.position==position; }))
        throw CodecError("richonline_combat_mine_duplicate");
    auto after=before;
    after.mines.push_back({position,owner,3});
    next_revision(after); return after;
}
std::optional<Bytes> plan_richonline_mine_explosion_wire(std::uint16_t game_id,
    std::int16_t position,RichonlineExplosionTrigger trigger) {
    if (position<0) throw CodecError("richonline_combat_position_invalid");
    switch (trigger) {
    case RichonlineExplosionTrigger::scheduled_expiry: return encode_richonline_mine_explosion4017(game_id,position);
    case RichonlineExplosionTrigger::stepped_on:
    case RichonlineExplosionTrigger::missile_chain: return {};
    }
    throw CodecError("richonline_combat_trigger_invalid");
}
RichonlineCombatDamagePlan plan_richonline_combat_damage(std::uint8_t victim,
    const RichonlineGameFundsSnapshot& before,RichonlineCombatEffect effect,
    const RichonlineActorStatus& attacker,const RichonlineActorStatus& defender,
    const RichonlineCombatDamageTerms& terms,RichonlineClientDamageApplication application,
    std::optional<RichonlineBossCards::PreparedConsumption> helmet) {
    if (victim>=8) throw CodecError("richonline_combat_actor_invalid");
    switch (effect) {
    case RichonlineCombatEffect::mine: case RichonlineCombatEffect::missile: case RichonlineCombatEffect::timed_bomb:
    case RichonlineCombatEffect::nuclear: case RichonlineCombatEffect::safe_nuclear: break;
    default: throw CodecError("richonline_combat_effect_invalid");
    }
    if (!terms.resolved_modifiers && (!terms.only_shared_status_and_flat_terms || attacker.possession || defender.possession))
        throw CodecError("richonline_combat_modifier_unverified");
    if (terms.resource_base_damage==0 || terms.resource_base_damage>maximum || terms.flat_attack<0 || terms.flat_defense<0)
        throw CodecError("richonline_combat_damage_terms_invalid");
    if (!before.funds.deposit) throw CodecError("richonline_combat_deposit_unknown");
    if (before.funds.cash>maximum || *before.funds.deposit>maximum)
        throw CodecError("richonline_combat_balance_invalid");
    if (application!=RichonlineClientDamageApplication::already_applied &&
        application!=RichonlineClientDamageApplication::by_queued_attack)
        throw CodecError("richonline_combat_application_invalid");
    if (helmet && effect!=RichonlineCombatEffect::missile && effect!=RichonlineCombatEffect::nuclear &&
        effect!=RichonlineCombatEffect::safe_nuclear) throw CodecError("richonline_combat_helmet_effect_invalid");
    RichonlineCombatDamagePlan out{victim,before,before.funds,0,false,application,helmet};
    if (helmet) {
        if (helmet->slot<0 || helmet->slot>=8 || helmet->card_id!=1076)
            throw CodecError("richonline_combat_helmet_plan_invalid");
        const auto index=static_cast<std::size_t>(helmet->slot);
        auto expected=helmet->source_inventory;
        if (expected[index].card_id!=1076 || expected[index].count<=0)
            throw CodecError("richonline_combat_helmet_plan_invalid");
        if (--expected[index].count==0) expected[index]={};
        if (expected!=helmet->remaining_inventory) throw CodecError("richonline_combat_helmet_plan_invalid");
        return out;
    }
    const auto mods=terms.resolved_modifiers.value_or(std::array<RichonlineCombatModifiers,2>{});
    out.damage=calculate_richonline_combat_damage(terms.resource_base_damage,attacker,defender,mods[0],mods[1],
        terms.attacker_modifiers_enabled,terms.flat_attack,terms.flat_defense);
    const auto total=static_cast<std::uint64_t>(before.funds.cash)+*before.funds.deposit;
    out.bankrupt=total<=out.damage;
    const auto cash_debit=std::min(out.damage,out.after.cash);
    out.after.cash-=cash_debit;
    const auto bank_debit=std::min(out.damage-cash_debit,*out.after.deposit);
    *out.after.deposit-=bank_debit;
    return out;
}
std::uint32_t richonline_regular_mine_chain_damage(std::uint32_t damage,std::uint32_t count) {
    if (count==0 || damage==0) throw CodecError("richonline_combat_chain_invalid");
    return rounded_damage(static_cast<double>(damage)*count*(1.0+0.05*(count-1)));
}
std::uint32_t richonline_mixed_mine_chain_damage(std::uint32_t adjusted,std::uint32_t raw,
    std::uint32_t super_hits,std::uint32_t normal,std::uint32_t super) {
    if (!adjusted || !raw || !normal || !super || adjusted>maximum || raw>maximum ||
        normal>maximum || super>maximum || super_hits>maximum)
        throw CodecError("richonline_combat_chain_invalid");
    const auto extra=static_cast<std::int64_t>(super_hits)*
        (static_cast<std::int64_t>(super)-normal);
    const auto regular=static_cast<std::int64_t>(raw)-extra;
    if (extra>maximum || extra < -static_cast<std::int64_t>(maximum) ||
        regular>maximum || regular < -static_cast<std::int64_t>(maximum))
        throw CodecError("richonline_combat_chain_overflow");
    const auto count=regular/normal;
    if (count<=0) return adjusted;
    const auto scaled=static_cast<double>(normal*count)*(1.0+0.05*static_cast<double>(count-1));
    if (!std::isfinite(scaled) || scaled>maximum)
        throw CodecError("richonline_combat_chain_overflow");
    // NEW truncates the raw bonus first, then stores ratio and final result as float.
    const auto raw_after=static_cast<std::int64_t>(scaled)+extra;
    if (raw_after<=0 || raw_after>maximum) throw CodecError("richonline_combat_chain_overflow");
    const auto ratio=static_cast<float>(adjusted)/static_cast<float>(raw);
    const auto result=static_cast<float>(static_cast<double>(ratio)*static_cast<float>(raw_after)+0.5);
    if (!std::isfinite(result) || static_cast<double>(result)>maximum)
        throw CodecError("richonline_combat_chain_overflow");
    return static_cast<std::uint32_t>(result);
}
bool richonline_combat_action_allowed(const RichonlineActorStatus& status) noexcept {
    return status.sleepwalking==0 && status.frozen==0;
}
RichonlineMineChainPlan plan_richonline_mine_chain(std::int16_t root,
    std::span<const RichonlineMine> mines,std::uint8_t range,const RichonlineCombatStep& step) {
    // NEW uses fixed 10-position scratch space: center + 4*range must fit.
    if (!step || range==0 || range>2) throw CodecError("richonline_combat_chain_range_invalid");
    std::map<std::int16_t,RichonlineMine> by_position;
    for (const auto& mine:mines) {
        if (mine.position<0 || mine.owner < -1 || mine.owner>=8 ||
            (mine.kind!=RichonlineMineKind::normal && mine.kind!=RichonlineMineKind::super) ||
            !by_position.emplace(mine.position,mine).second)
            throw CodecError("richonline_combat_mine_invalid");
    }
    if (!by_position.contains(root)) throw CodecError("richonline_combat_chain_root_missing");
    RichonlineMineChainPlan plan;
    std::set<std::int16_t> seen{root},affected;
    const std::function<void(std::int16_t)> visit=[&](std::int16_t origin) {
        RichonlineMineChainPlan::Blast blast{by_position.at(origin),{origin}};
        std::vector<std::int16_t> children;
        for (std::uint8_t direction=0;direction<4;++direction) {
            auto position=origin;
            for (std::uint8_t distance=0;distance<range;++distance) {
                const auto next=step(position,direction);
                if (!next) break;
                if (*next<0 || *next==position) throw CodecError("richonline_combat_topology_invalid");
                position=*next; blast.positions.push_back(position);
                if (by_position.contains(position) && seen.insert(position).second) children.push_back(position);
            }
        }
        for (const auto position:blast.positions) if (affected.insert(position).second) plan.affected_positions.push_back(position);
        plan.detonated_mines.push_back(origin); plan.blasts.push_back(std::move(blast));
        for (const auto child:children) visit(child);
    };
    visit(root); return plan;
}
Bytes encode_richonline_boss_noninventory_attack(std::uint16_t game_id,RichonlineCombatEffect effect,
    std::int8_t attacker,std::int16_t target,const RichonlineActorStatus& status,bool visible) {
    if (attacker<0 || attacker>=8 || target<0) throw CodecError("richonline_combat_attack_invalid");
    if (!richonline_combat_action_allowed(status)) throw CodecError("richonline_combat_actor_controlled");
    if (!visible) throw CodecError("richonline_combat_target_out_of_view");
    std::uint16_t opcode;
    switch(effect) {
    case RichonlineCombatEffect::mine:opcode=0x40bd;break;
    case RichonlineCombatEffect::missile:opcode=0x40bf;break;
    case RichonlineCombatEffect::nuclear:opcode=0x40cc;break;
    case RichonlineCombatEffect::safe_nuclear:opcode=0x40d5;break;
    default:throw CodecError("richonline_combat_attack_not_implemented");
    }
    Bytes out; append_le(out,opcode,2);
    append_le(out,game_id,2);
    out.push_back(0); // Safe unused slot; bank=-1 is the explicit no-consumption policy.
    out.push_back(0xff);
    append_le(out,static_cast<std::uint16_t>(target),2);
    if (effect!=RichonlineCombatEffect::mine) {
        out.push_back(static_cast<std::uint8_t>(attacker));
        out.push_back(0); // Ordinary actor-use presentation, not silent map effect.
    }
    return out;
}
std::vector<std::int16_t> richonline_attack_footprint(RichonlineCombatEffect effect,std::int16_t target,
    std::uint16_t width,std::uint16_t height,const RichonlineCombatResources& resources) {
    const auto size=static_cast<std::uint32_t>(width)*height;
    if (!width || !height || size>32768 || target<0 || static_cast<std::uint32_t>(target)>=size)
        throw CodecError("richonline_combat_map_invalid");
    std::uint8_t radius;
    switch(effect) {
    case RichonlineCombatEffect::missile:radius=resources.missile_radius;break;
    case RichonlineCombatEffect::nuclear:radius=resources.nuclear_radius;break;
    case RichonlineCombatEffect::safe_nuclear:radius=resources.safe_nuclear_radius;break;
    default:throw CodecError("richonline_combat_footprint_effect_invalid");
    }
    if (!radius || radius>(effect==RichonlineCombatEffect::missile?1:2))
        throw CodecError("richonline_combat_resource_range");
    const auto x=target%width,y=target/width;
    std::vector<std::int16_t> result;
    for (int row=std::max(0,y-radius);row<=std::min<int>(height-1,y+radius);++row)
        for (int col=std::max(0,x-radius);col<=std::min<int>(width-1,x+radius);++col)
            result.push_back(static_cast<std::int16_t>(row*width+col));
    return result;
}
bool richonline_attack_hits_actor(RichonlineCombatEffect effect,std::int8_t attacker,std::int8_t victim,
    bool active,bool hospital,bool prison,bool frozen) {
    if (attacker<0 || attacker>=8 || victim<0 || victim>=8) throw CodecError("richonline_combat_actor_invalid");
    if (effect!=RichonlineCombatEffect::missile && effect!=RichonlineCombatEffect::nuclear && effect!=RichonlineCombatEffect::safe_nuclear)
        throw CodecError("richonline_combat_footprint_effect_invalid");
    return active && !hospital && !prison && !frozen && (effect!=RichonlineCombatEffect::safe_nuclear || attacker!=victim);
}
RichonlineBossBlastBuildingEffect richonline_boss_blast_building_effect(RichonlineCombatEffect effect,
    std::int8_t kind,std::uint8_t level,bool owned,bool protected_owner) {
    if (level>5) throw CodecError("richonline_combat_building_level_invalid");
    if (effect!=RichonlineCombatEffect::missile && effect!=RichonlineCombatEffect::nuclear && effect!=RichonlineCombatEffect::safe_nuclear)
        throw CodecError("richonline_combat_footprint_effect_invalid");
    if (kind==10 && owned) return RichonlineBossBlastBuildingEffect::remove_ownership;
    if (effect==RichonlineCombatEffect::missile) return RichonlineBossBlastBuildingEffect::none;
    if (level>0) return RichonlineBossBlastBuildingEffect::lower_one_level;
    return owned && !protected_owner?RichonlineBossBlastBuildingEffect::remove_ownership:RichonlineBossBlastBuildingEffect::none;
}
}
