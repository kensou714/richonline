#include "richonline_npc.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <limits>

namespace richnet {
namespace {
std::string_view trim(std::string_view s) {
    const auto p=s.find_first_not_of(" \t\r");
    return p==s.npos ? std::string_view{} : s.substr(p,s.find_last_not_of(" \t\r")-p+1);
}
int integer(std::string_view s) {
    int n=0; const auto r=std::from_chars(s.data(),s.data()+s.size(),n);
    if(s.empty() || r.ec!=std::errc{} || r.ptr!=s.data()+s.size()) throw CodecError("richonline_npc_resource_invalid");
    return n;
}
Bytes packet(std::uint16_t opcode,std::uint16_t game) {
    Bytes bytes; append_le(bytes,opcode,2); append_le(bytes,game,2); return bytes;
}
}
RichonlineFortuneCardRequest decode_richonline_fortune_card(View bytes) {
    if(bytes.size()!=6 || read_le(bytes.first(2))!=131) throw CodecError("richonline_fortune_card_wire_invalid");
    const auto slot=static_cast<std::int8_t>(bytes[4]),bank=static_cast<std::int8_t>(bytes[5]);
    if(slot<0 || slot>=8 || bank!=0) throw CodecError("richonline_fortune_card_inventory_invalid");
    return {static_cast<std::uint16_t>(read_le(bytes.subspan(2,2))),slot,bank};
}
RichonlineDeityRouletteRequest decode_richonline_deity_roulette(View bytes) {
    if(bytes.size()!=6 || read_le(bytes.first(2))!=34 || bytes[4]!=1)
        throw CodecError("richonline_deity_roulette_wire_invalid");
    return {static_cast<std::uint16_t>(read_le(bytes.subspan(2,2))),bytes[5]};
}
std::uint8_t parse_richonline_npc_affix(std::string_view text,std::int8_t kind) {
    if(kind<0 || kind>32) throw CodecError("richonline_npc_resource_kind_invalid");
    if(text.empty() || text.size()>4U*1024U*1024U || text.find('\0')!=text.npos) throw CodecError("richonline_npc_resource_invalid");
    std::optional<int> index,affix,fortune; bool section=false;
    const auto finish=[&] {
        if(section && index==kind) {
            if(fortune || !affix || *affix<=0 || *affix>127) throw CodecError("richonline_npc_resource_invalid");
            fortune=*affix;
        }
    };
    while(!text.empty()) {
        const auto n=text.find('\n'); auto line=trim(text.substr(0,n));
        text=n==text.npos ? std::string_view{} : text.substr(n+1);
        if(line.empty() || line.starts_with("//") || line.front()==';') continue;
        if(line.front()=='[') { finish(); section=line=="[NPC]"; index.reset(); affix.reset(); continue; }
        if(!section) continue;
        const auto equals=line.find('='); if(equals==line.npos) throw CodecError("richonline_npc_resource_invalid");
        const auto key=trim(line.substr(0,equals)), value=trim(line.substr(equals+1));
        if(key=="indx") { if(index) throw CodecError("richonline_npc_resource_invalid"); index=integer(value); }
        if(key=="affix") { if(affix) throw CodecError("richonline_npc_resource_invalid"); affix=integer(value); }
    }
    finish(); if(!fortune) throw CodecError("richonline_npc_affix_resource_missing");
    return static_cast<std::uint8_t>(*fortune);
}
std::uint8_t load_richonline_npc_affix(const std::filesystem::path& root,std::int8_t kind) {
    const auto bytes=load_original_kpd(root/"Data"/"Npc.kpd");
    return parse_richonline_npc_affix({reinterpret_cast<const char*>(bytes.data()),bytes.size()},kind);
}
RichonlineNpcRules RichonlineNpcRules::parse(std::string_view text) { return {parse_richonline_npc_affix(text,3)}; }
RichonlineNpcRules RichonlineNpcRules::load(const std::filesystem::path& root) { return {load_richonline_npc_affix(root,3)}; }
RichonlineFortunePlan plan_richonline_fortune(const RichonlineFortuneContext& ctx,
    const RichonlineNpcRules& rules,const RichonlineChanceResources& resources,const RichonlineChanceEventTable& names,
    std::string_view map,std::array<std::int16_t,2> chosen,const RichonlineChanceInventory& inventory,
    const RichonlineActorStatus& status,const RichonlineGameFundsSnapshot& funds) {
    if(ctx.actor>=4 || ctx.position<0 || rules.fortune_affix_turns==0 || rules.fortune_affix_turns>127)
        throw CodecError("richonline_fortune_context_invalid");
    for(const auto& slot:inventory)
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.count<=0 || !resources.contains_card(slot.card_id))))
            throw CodecError("richonline_fortune_inventory_invalid");
    auto after=inventory;
    RichonlineNpcContinuation continuation;
    std::vector<Bytes> messages;
    switch(ctx.origin) {
    case RichonlineNpcOrigin::ground: {
        if(ctx.card) throw CodecError("richonline_fortune_context_invalid");
        auto stop=packet(0x4013,ctx.game_id); append_le(stop,static_cast<std::uint16_t>(ctx.position),2);
        messages.push_back(std::move(stop)); continuation=RichonlineNpcContinuation::landing_phase1; break;
    }
    case RichonlineNpcOrigin::temple:
        if(ctx.card) throw CodecError("richonline_fortune_context_invalid");
        continuation=RichonlineNpcContinuation::landing_phase6; break;
    case RichonlineNpcOrigin::fortune_card1070: {
        if(!ctx.card || ctx.synthetic || ctx.card->slot<0 || ctx.card->slot>=8 || ctx.card->bank!=0)
            throw CodecError("richonline_fortune_context_invalid");
        auto& used=after[static_cast<std::size_t>(ctx.card->slot)];
        if(used.card_id!=1070 || used.count<=0) throw CodecError("richonline_fortune_card_missing");
        if(--used.count==0) used={};
        auto attached=packet(0x40d3,ctx.game_id);
        attached.push_back(static_cast<std::uint8_t>(ctx.card->slot)); attached.push_back(static_cast<std::uint8_t>(ctx.card->bank));
        messages.push_back(std::move(attached)); continuation=RichonlineNpcContinuation::restore_action; break;
    }
    default: throw CodecError("richonline_fortune_context_invalid");
    }
    if(!ctx.synthetic) {
        // 65F0C0 attempts both insertions in order; each insertion may trigger
        // a resource combination and release room for the second card.
        for(const auto card:chosen) {
            if(!resources.contains_card(card)) throw CodecError("richonline_fortune_reward_invalid");
            after=resources.add(map,card,1,after);
        }
        // Covers the longer full-bag wording regardless of either add result.
        names.card_panel_bytes(chosen,false,true);
        auto reward=packet(0x4023,ctx.game_id);
        for(const auto card:chosen) append_le(reward,static_cast<std::uint16_t>(card),2);
        messages.push_back(std::move(reward));
    }
    auto after_status=status;
    // NEW673D50 replaces the old god through6050 before attaching fortune.
    // Temple callers have already attached it; do not detach during reward-only planning.
    if(ctx.origin==RichonlineNpcOrigin::fortune_card1070 && after_status.possession)
        richonline_detach_possession(after_status);
    after_status.possession=3;
    return {std::move(messages),inventory,after,status,after_status,funds,funds.funds,
        rules.fortune_affix_turns,continuation,ctx.origin==RichonlineNpcOrigin::ground,false};
}
RichonlineDeityMoneyPlan plan_richonline_deity_money(const RichonlineDeityMoneyContext& ctx,
    std::int16_t amount,const RichonlineActorStatus& status,
    const std::array<RichonlineGameFundsSnapshot,2>& before) {
    if(ctx.actor>=2 || amount<0 || (status.possession!=0 && status.possession!=1))
        throw CodecError("richonline_deity_money_context_invalid");
    RichonlineNpcContinuation continuation;
    switch(ctx.origin) {
    case RichonlineDeityMoneyOrigin::ground: continuation=RichonlineNpcContinuation::landing_phase1; break;
    case RichonlineDeityMoneyOrigin::temple: continuation=RichonlineNpcContinuation::landing_phase6; break;
    case RichonlineDeityMoneyOrigin::summoned_card: continuation=RichonlineNpcContinuation::restore_action; break;
    default: throw CodecError("richonline_deity_money_context_invalid");
    }
    const auto other=static_cast<std::uint8_t>(1U-ctx.actor);
    const bool wealth=status.possession==0;
    if(wealth && ctx.actor44[0]==ctx.actor44[1])
        throw CodecError("richonline_deity_money_same_group_unimplemented");
    const auto payer=wealth ? other : ctx.actor;
    const auto receiver=wealth ? ctx.actor : other;
    auto after=std::array{before[0].funds,before[1].funds};
    const auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    for(const auto& balance:after)
        if(!balance.deposit || balance.cash>maximum || *balance.deposit>maximum ||
            balance.cash>maximum-*balance.deposit || balance.tickets>maximum ||
            (balance.reserve && *balance.reserve>maximum)) throw CodecError("richonline_deity_money_balance_invalid");
    const auto fee=static_cast<std::uint32_t>(amount);
    if(after[receiver].cash+*after[receiver].deposit>maximum-fee)
        throw CodecError("richonline_deity_money_balance_overflow");
    after[receiver].cash+=fee;
    const auto paid_cash=std::min(after[payer].cash,fee);
    after[payer].cash-=paid_cash;
    const auto deposit_cost=fee-paid_cash;
    *after[payer].deposit-=std::min(*after[payer].deposit,deposit_cost);
    const bool insolvent=after[payer].cash==0 && *after[payer].deposit==0;
    auto response=packet(0x4022,ctx.game_id);
    append_le(response,static_cast<std::uint16_t>(amount),2);
    // 4022+6 becomes local6040+5: wait when a depleted NPC0 donor needs
    // settlement. NPC1 already blocks on its own debit's return value.
    response.push_back(insolvent ? 1 : 0);
    return {std::move(response),before,after,insolvent ? std::optional{payer} : std::nullopt,
        continuation,insolvent,false};
}
bool commit_richonline_deity_money(RichonlineGameLedger& ledger,const RichonlineDeityMoneyPlan& plan,
    const std::function<bool()>& authorize) {
    if(ledger.actor_count()!=2) throw CodecError("richonline_deity_money_actor_count_invalid");
    const std::array<RichonlineGameFundsUpdate,2> updates{{{0,plan.before[0],plan.after[0]},
        {1,plan.before[1],plan.after[1]}}};
    return ledger.commit_batch(updates,authorize);
}
RichonlineWealthCardRequest decode_richonline_wealth_card(View bytes) {
    if(bytes.size()!=6 || read_le(bytes.first(2))!=130) throw CodecError("richonline_wealth_card_wire_invalid");
    const auto slot=static_cast<std::int8_t>(bytes[4]),bank=static_cast<std::int8_t>(bytes[5]);
    if(slot<0 || slot>=8 || bank!=0) throw CodecError("richonline_wealth_card_inventory_invalid");
    return {static_cast<std::uint16_t>(read_le(bytes.subspan(2,2))),slot,bank};
}
RichonlineWealthCardPlan plan_richonline_wealth_card(std::uint16_t game,const RichonlineWealthCardRequest& request,
    std::uint8_t affix,const RichonlineChanceResources& resources,
    const RichonlineChanceInventory& inventory,const RichonlineActorStatus& status) {
    if(request.slot<0 || request.slot>=8 || request.bank!=0 || affix==0 || affix>127)
        throw CodecError("richonline_wealth_card_context_invalid");
    for(const auto& slot:inventory)
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.count<=0 || !resources.contains_card(slot.card_id))))
            throw CodecError("richonline_wealth_card_inventory_invalid");
    auto after=inventory; auto& used=after[static_cast<std::size_t>(request.slot)];
    if(used.card_id!=1069 || used.count<=0) throw CodecError("richonline_wealth_card_missing");
    if(--used.count==0) used={};
    auto response=packet(0x40d2,game);
    response.push_back(static_cast<std::uint8_t>(request.slot)); response.push_back(static_cast<std::uint8_t>(request.bank));
    auto after_status=status;
    // NEW673AF0 queues6050 before6051, including replacement of the same god.
    if(after_status.possession) richonline_detach_possession(after_status);
    after_status.possession=0;
    return {std::move(response),inventory,after,status,after_status,affix,34,RichonlineDeityMoneyOrigin::summoned_card};
}
std::array<std::int8_t,4> select_richonline_badluck_half(RichonlineChanceInventory inventory,
    std::uint8_t limit,const std::function<std::size_t(std::size_t)>& choose) {
    if(limit>4 || !choose) throw CodecError("richonline_badluck_selection_invalid");
    std::size_t units=0;
    for(const auto& slot:inventory) {
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.card_id<0 || slot.count<=0)))
            throw CodecError("richonline_badluck_inventory_invalid");
        units+=static_cast<std::size_t>(slot.count);
    }
    const auto losses=std::min(units/2,static_cast<std::size_t>(limit));
    std::array<std::int8_t,4> selected{-1,-1,-1,-1};
    for(std::size_t trial=0;trial<losses;++trial) {
        auto draw=choose(units);
        if(draw>=units) throw CodecError("richonline_badluck_random_out_of_range");
        for(std::size_t index=0;index<inventory.size();++index) {
            const auto count=static_cast<std::size_t>(inventory[index].count);
            if(draw>=count) {draw-=count;continue;}
            selected[trial]=static_cast<std::int8_t>(index);
            if(--inventory[index].count==0) inventory[index]={};
            --units;break;
        }
    }
    return selected;
}
RichonlineBadluckPlan plan_richonline_badluck(std::uint16_t game,RichonlineDeityMoneyOrigin origin,
    bool synthetic,std::array<std::int8_t,4> slots,const RichonlineChanceResources& resources,
    const RichonlineChanceInventory& inventory,const RichonlineActorStatus& status,const RichonlineChanceEventTable& names) {
    if(status.possession!=2) throw CodecError("richonline_badluck_possession_missing");
    RichonlineNpcContinuation continuation;
    switch(origin) {
    case RichonlineDeityMoneyOrigin::ground: continuation=RichonlineNpcContinuation::landing_phase1; break;
    case RichonlineDeityMoneyOrigin::temple: continuation=RichonlineNpcContinuation::landing_phase6; break;
    case RichonlineDeityMoneyOrigin::summoned_card: continuation=RichonlineNpcContinuation::restore_action; break;
    default: throw CodecError("richonline_badluck_origin_invalid");
    }
    for(const auto& slot:inventory)
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.count<=0 || !resources.contains_card(slot.card_id))))
            throw CodecError("richonline_badluck_inventory_invalid");
    auto after=inventory;
    auto response=packet(0x4024,game);
    std::vector<std::int16_t> lost;
    bool ended=false;
    for(const auto index:slots) {
        if(index==-1) ended=true;
        else {
            if(index<0 || index>=8 || ended || synthetic) throw CodecError("richonline_badluck_slot_invalid");
            auto& slot=after[static_cast<std::size_t>(index)];
            if(slot.card_id==-1 || slot.count<=0) throw CodecError("richonline_badluck_card_missing");
            lost.push_back(slot.card_id);
            if(--slot.count==0) slot={};
        }
        response.push_back(static_cast<std::uint8_t>(index));
    }
    std::vector<Bytes> messages;
    if(!lost.empty()) static_cast<void>(names.card_panel_bytes(lost,true,false));
    if(!synthetic) messages.push_back(std::move(response));
    return {std::move(messages),inventory,after,continuation,false};
}
RichonlineTicketChestRules RichonlineTicketChestRules::parse(std::string_view text) {
    if(text.empty() || text.size()>4U*1024U*1024U || text.find('\0')!=text.npos)
        throw CodecError("richonline_chest_resource_invalid");
    std::optional<int> index,value,tickets; bool section=false;
    const auto finish=[&] {
        if(section && index==14) {
            if(tickets || !value || *value<=0 || *value>32767)
                throw CodecError("richonline_chest_resource_invalid");
            tickets=*value;
        }
    };
    while(!text.empty()) {
        const auto n=text.find('\n'); auto line=trim(text.substr(0,n));
        text=n==text.npos ? std::string_view{} : text.substr(n+1);
        if(line.empty() || line.starts_with("//") || line.front()==';') continue;
        if(line.front()=='[') { finish(); section=line=="[ITEM]"; index.reset(); value.reset(); continue; }
        if(!section) continue;
        const auto equals=line.find('='); if(equals==line.npos) throw CodecError("richonline_chest_resource_invalid");
        const auto key=trim(line.substr(0,equals)), val=trim(line.substr(equals+1));
        if(key=="indx") { if(index) throw CodecError("richonline_chest_resource_invalid"); index=integer(val); }
        if(key=="value") { if(value) throw CodecError("richonline_chest_resource_invalid"); value=integer(val); }
    }
    finish(); if(!tickets) throw CodecError("richonline_chest_resource_missing");
    return {static_cast<std::uint16_t>(*tickets)};
}
RichonlineTicketChestRules RichonlineTicketChestRules::load(const std::filesystem::path& root) {
    const auto bytes=load_original_kpd(root/"Data"/"GValue.kpd");
    return parse({reinterpret_cast<const char*>(bytes.data()),bytes.size()});
}
RichonlineTicketChestPlan plan_richonline_ticket_chest(const RichonlineTicketChestRules& rules,
    bool synthetic,const RichonlineActorStatus& status,const RichonlineGameFundsSnapshot& before) {
    if(rules.tickets==0 || rules.tickets>32767) throw CodecError("richonline_chest_reward_invalid");
    const bool remove=status.possession!=7 && status.sleepwalking==0;
    auto after=before.funds;
    if(remove && !synthetic) {
        constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
        if(after.tickets>maximum-rules.tickets) throw CodecError("richonline_chest_tickets_overflow");
        after.tickets+=rules.tickets;
    }
    return {before,after,remove,RichonlineNpcContinuation::landing_phase1,false};
}
RichonlineSleepDeityPlan plan_richonline_sleep_deity(std::uint8_t affix,
    const RichonlineChanceResources& resources,const RichonlineChanceInventory& inventory,
    const RichonlineActorStatus& status,RichonlineSleepProtection protection) {
    if(status.possession!=7 || affix==0 || affix>127)
        throw CodecError("richonline_sleep_deity_context_invalid");
    for(const auto& slot:inventory)
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.count<=0 || !resources.contains_card(slot.card_id))))
            throw CodecError("richonline_sleep_deity_inventory_invalid");
    if((!protection.triggered && protection.consumed_inventory_slot) ||
        (protection.triggered && (!protection.consumed_inventory_slot || status.protected_from_status)))
        throw CodecError("richonline_sleep_deity_protection_invalid");
    auto after=inventory; auto after_status=status;
    const bool blocked=status.protected_from_status || protection.triggered;
    if(protection.triggered) {
        const auto index=*protection.consumed_inventory_slot;
        if(index>=8) throw CodecError("richonline_sleep_deity_protection_invalid");
        auto& card=after[index];
        if(card.card_id!=1071 || card.count<=0) throw CodecError("richonline_sleep_deity_protection_missing");
        if(--card.count==0) card={};
    }
    if(blocked) richonline_detach_possession(after_status);
    return {inventory,after,status,after_status,blocked ? std::uint8_t{0} : affix,blocked,protection.consumed_inventory_slot};
}
}
