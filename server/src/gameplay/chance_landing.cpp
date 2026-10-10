#include "richonline_chance_landing.hpp"
#include "richonline_boss_landing.hpp"
#include <algorithm>
#include <charconv>
#include <limits>
#include <set>

namespace richnet {
namespace {
std::optional<std::size_t> news_column(std::int8_t static_type) {
    // NEW EMP -> event.dat -> NP textures prove 68 blue, 69 red, 70 yellow.
    // BwNews columns gate eligibility; server_weight still defines our lottery.
    switch(static_type) {
        case 68: return 0;
        case 69: return 1;
        case 70: return 2;
        default: return {};
    }
}
std::size_t choose(const RichonlineRouteChooser& random,std::size_t bound) {
    if(!random || !bound) throw CodecError("richonline_chance_landing_rng_invalid");
    const auto selected=random(bound);
    if(selected>=bound) throw CodecError("richonline_chance_landing_rng_invalid");
    return selected;
}
std::int32_t scalar(const RichonlineRouteChooser& random,const RichonlineChanceEvent& event) {
    const auto low=static_cast<std::int64_t>(event.raw_parameters[0]);
    const auto high=static_cast<std::int64_t>(event.raw_parameters[1]);
    if(low<0 || high<low) throw CodecError("richonline_chance_landing_parameter_bounds_invalid");
    const auto range=high-low+1;
    if(static_cast<std::uint64_t>(range)>std::numeric_limits<std::size_t>::max())
        throw CodecError("richonline_chance_landing_parameter_bounds_invalid");
    return static_cast<std::int32_t>(low+static_cast<std::int64_t>(choose(random,static_cast<std::size_t>(range))));
}
bool candidate_exclusion(std::string_view code) {
    return code=="bankruptcy_flow_required" || code=="synthetic_card_rewards_disabled" ||
        code=="playable_reward_pool_empty" || code=="synthesized_reward_not_playable" ||
        code=="event_followup_not_closed" || code=="motion_priority_unverified" || code=="richonline_chance_event_percentage_overflow" ||
        code=="richonline_chance_event_balance_overflow";
}
bool allowed(const RichonlineChanceLandingPolicy& policy,std::int16_t card) {
    return std::find(policy.playable_reward_cards.begin(),policy.playable_reward_cards.end(),card)!=policy.playable_reward_cards.end();
}
std::vector<std::int16_t> candidates(const RichonlineChanceEvent& event,const RichonlineChanceLandingPolicy& policy) {
    if(event.category==4) return policy.playable_reward_cards;
    std::vector<std::int16_t> result; std::string_view text=event.candidates;
    while(!text.empty()) {
        const auto comma=text.find(','); const auto item=text.substr(0,comma); std::int32_t id=0;
        const auto parsed=std::from_chars(item.data(),item.data()+item.size(),id);
        if(parsed.ec!=std::errc{} || parsed.ptr!=item.data()+item.size() || id<1 || id>32767)
            throw CodecError("richonline_chance_landing_candidate_invalid");
        if(allowed(policy,static_cast<std::int16_t>(id))) result.push_back(static_cast<std::int16_t>(id));
        if(comma==text.npos) break; text.remove_prefix(comma+1);
    }
    return result;
}
}
RichonlineChanceLandingPolicy make_richonline_closed_chance_policy(const RichonlineChanceEventTable& table,
    std::string_view map,std::vector<std::int16_t> cards,bool motion,std::array<std::uint8_t,2> opaque) {
    RichonlineChanceLandingPolicy policy{"native-color-uniform-closed-events-v2",std::string(map),{},std::move(cards),{68,69,70},motion,opaque};
    for(std::size_t i=0;i<table.size(map);++i) {
        const auto& event=table.event(map,static_cast<std::int32_t>(i));
        if(event.category<=6 || (motion && event.category<=9)) policy.entries.push_back({event.id,1});
    }
    return policy;
}
RichonlineChanceLandingAttempt prepare_richonline_chance_landing(const RichonlineChanceEventTable& table,
    const RichonlineChanceResources& resources,const RichonlineStatusRules& status_rules,
    const RichonlineChanceLandingPolicy& policy,const RichonlineLandingContext& context,std::uint16_t game,
    const RichonlineGameFundsSnapshot& funds,const RichonlineChanceInventory& inventory,const RichonlineRouteChooser& random) {
    const auto column=news_column(context.static_type);
    if(!column || !richonline_news_landing_allowed(context) ||
        std::find(policy.static_types.begin(),policy.static_types.end(),context.static_type)==policy.static_types.end())
        return {RichonlineChanceLandingDisposition::not_applicable,{}, {}};
    if(policy.name.empty() || policy.map_name.empty() || policy.entries.empty() || !random)
        throw CodecError("richonline_chance_landing_policy_invalid");
    for(const auto& slot:inventory) {
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 &&
            (slot.count<=0 || !resources.contains_card(slot.card_id))))
            throw CodecError("richonline_chance_landing_inventory_invalid");
    }
    const auto& state=context.actor_status;
    for(const auto turns:{state.one_step,state.six_steps,state.turtle,state.stay,state.sleepwalking,state.frozen,
        state.attack_turns,state.damage_turns}) if(turns>127) throw CodecError("richonline_chance_landing_status_invalid");
    if(state.one_step && state.six_steps) throw CodecError("richonline_chance_landing_status_invalid");
    std::set<std::int16_t> ids;
    for(const auto& entry:policy.entries) {
        if(!entry.server_weight || !ids.insert(entry.event).second) throw CodecError("richonline_chance_landing_policy_invalid");
        static_cast<void>(table.event(policy.map_name,entry.event));
    }
    std::set<std::int16_t> card_ids;
    for(const auto card:policy.playable_reward_cards)
        if(!resources.contains_card(card) || !card_ids.insert(card).second) throw CodecError("richonline_chance_landing_policy_invalid");
    RichonlineChanceLandingAttempt attempt{RichonlineChanceLandingDisposition::no_closed_event,{}, {}};
    struct Option { RichonlinePreparedChanceLanding plan; std::uint32_t weight; };
    std::vector<Option> options; std::size_t total_weight=0;
    for(const auto& entry:policy.entries) {
        const auto& event=table.event(policy.map_name,entry.event);
        if(event.raw_weights[*column]<=0) {
            attempt.excluded_events.push_back(std::to_string(event.id)+":event_tile_color_mismatch");
            continue;
        }
        RichonlinePreparedChanceLanding plan{context.actor_slot,event.id,event.category,policy.name,{},funds,funds.funds,
            inventory,inventory,context.actor_status,context.actor_status};
        try {
            if(event.category<=3) {
                if(!funds.funds.deposit || funds.funds.cash>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
                    *funds.funds.deposit>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
                    throw CodecError("money_snapshot_unavailable");
                const auto result=plan_richonline_chance_money(table,policy.map_name,event.id,game,scalar(random,event),
                    {static_cast<std::int32_t>(funds.funds.cash),static_cast<std::int32_t>(*funds.funds.deposit)},policy.opaque6_7);
                if(result.insolvent || !result.client_continues_phase2) throw CodecError("bankruptcy_flow_required");
                plan.packet=result.packet; plan.updated_funds.cash=static_cast<std::uint32_t>(result.after.cash);
                plan.updated_funds.deposit=static_cast<std::uint32_t>(result.after.deposit);
            } else if(event.category<=6) {
                if(context.synthetic_actor) throw CodecError("synthetic_card_rewards_disabled");
                std::vector<std::int32_t> values;
                if(event.category==6) {
                    std::vector<std::int32_t> slots;
                    for(std::size_t i=0;i<inventory.size();++i) if(inventory[i].card_id!=-1) slots.push_back(static_cast<std::int32_t>(i));
                    const auto n=std::min(slots.size(),static_cast<std::size_t>(scalar(random,event)));
                    for(std::size_t i=0;i<n;++i) { const auto at=choose(random,slots.size()); values.push_back(slots[at]); slots.erase(slots.begin()+static_cast<std::ptrdiff_t>(at)); }
                } else {
                    const auto pool=candidates(event,policy);
                    if(pool.empty()) throw CodecError("playable_reward_pool_empty");
                    const auto count=event.category==5 ? 1 : scalar(random,event);
                    if(count<0 || count>8) throw CodecError("reward_count_outside_inventory");
                    for(std::int32_t i=0;i<count;++i) values.push_back(pool[choose(random,pool.size())]);
                }
                const auto result=plan_richonline_chance_cards(table,resources,policy.map_name,event.id,game,values,inventory,policy.opaque6_7);
                for(const auto& slot:result.after) if(slot.card_id!=-1 && !allowed(policy,slot.card_id) &&
                    std::find(inventory.begin(),inventory.end(),slot)==inventory.end()) throw CodecError("synthesized_reward_not_playable");
                plan.packet=result.packet; plan.updated_inventory=result.after;
            } else if(event.category<=9 && policy.enable_motion_status) {
                const auto result=plan_richonline_chance_status(table,policy.map_name,event.id,game,{},context.actor_status,status_rules,{false,{}},policy.opaque6_7);
                // NEW client duration mutations are known, but the interaction
                // of six-step and turtle dice is not yet proven by the client.
                if(result.after.six_steps && result.after.turtle)
                    throw CodecError("motion_priority_unverified");
                plan.packet=result.packet; plan.updated_status=result.after;
            } else throw CodecError("event_followup_not_closed");
        } catch(const CodecError& error) {
            if(!candidate_exclusion(error.what())) throw;
            attempt.excluded_events.push_back(std::to_string(event.id)+":"+error.what()); continue;
        }
        if(entry.server_weight>std::numeric_limits<std::size_t>::max()-total_weight) throw CodecError("richonline_chance_landing_weight_overflow");
        total_weight+=entry.server_weight; options.push_back({std::move(plan),entry.server_weight});
    }
    if(options.empty()) return attempt;
    auto selected=choose(random,total_weight);
    for(auto& option:options) {
        if(selected<option.weight) { attempt.disposition=RichonlineChanceLandingDisposition::prepared; attempt.prepared=std::move(option.plan); return attempt; }
        selected-=option.weight;
    }
    throw CodecError("richonline_chance_landing_weight_invalid");
}
}
