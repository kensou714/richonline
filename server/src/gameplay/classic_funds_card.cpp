#include "richonline_classic_funds_card.hpp"
#include "lua_wire.hpp"
#include <algorithm>
#include <limits>

namespace richnet {
RichonlineClassicFundsCardRequest decode_richonline_classic_funds_card(View packet) {
    if(packet.size()<6) throw CodecError("richonline_classic_funds_card_wire_invalid");
    const auto opcode=read_le(packet.first(2));
    if((opcode!=114 && opcode!=115 && opcode!=166) ||
        packet.size()!=(opcode==166?6U:8U) || packet[4]>=8 || packet[5]!=0 ||
        (opcode!=166 && packet[6]>=4)) throw CodecError("richonline_classic_funds_card_wire_invalid");
    return {static_cast<std::uint16_t>(opcode),static_cast<std::uint16_t>(read_le(packet.subspan(2,2))),
        packet[4],opcode==166?std::nullopt:std::optional{packet[6]}};
}
RichonlineClassicFundsCardPlan prepare_richonline_classic_funds_card(View packet,std::uint16_t calendar,
    const RichonlinePlayerCards& cards,const RichonlineGameLedger& ledger,
    std::span<const std::uint8_t> active,const std::shared_ptr<LuaServer>& script) {
    const auto use=decode_richonline_classic_funds_card(packet);
    const auto actor=cards.actor_slot();
    if(cards.game_mode()!=0 || use.calendar!=calendar || active.size()<2 || active.size()>4 ||
        active.size()!=ledger.actor_count() || actor>=active.size() || !active[actor] ||
        std::ranges::any_of(active,[](auto value){return value>1;}) ||
        (use.target && (*use.target>=active.size() || *use.target==actor || !active[*use.target])))
        throw CodecError("richonline_classic_funds_card_context_invalid");
    const std::int16_t card_id=use.opcode==114?1051:use.opcode==115?1052:508;
    const auto consumed=cards.prepare_consumption(static_cast<std::int8_t>(use.inventory_slot),card_id);
    if(!consumed) throw CodecError("richonline_classic_funds_card_not_owned");
    RichonlineClassicFundsCardPlan plan;
    plan.cards_=&cards;plan.ledger_=&ledger;
    plan.before_inventory_=consumed->source_inventory;plan.after_inventory_=consumed->remaining_inventory;
    plan.active_.assign(active.begin(),active.end());
    std::vector<RichonlineGameFundsSnapshot> funds;
    for(std::uint8_t slot=0;slot<active.size();++slot) funds.push_back(ledger.snapshot(slot));
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if(use.opcode==166) {
        std::uint64_t sum=0;
        for(std::uint8_t slot=0;slot<active.size();++slot) if(active[slot]) {
            if(!funds[slot].funds.deposit) throw CodecError("richonline_classic_funds_card_deposit_unknown");
            sum+=*funds[slot].funds.deposit;
            plan.funds_.push_back({slot,funds[slot],funds[slot].funds});
        }
        if(sum>maximum) throw CodecError("richonline_classic_funds_card_sum_overflow");
        // 6799C0的mode0分支使用存款和活动人数；商为0时置1，不改现金。
        const auto average=std::max(1U,static_cast<std::uint32_t>(sum/plan.funds_.size()));
        for(auto& update:plan.funds_) update.after.deposit=average;
    } else {
        const auto target=*use.target;
        auto source_after=funds[actor].funds,target_after=funds[target].funds;
        if(use.opcode==114) {
            if(!source_after.deposit || !target_after.deposit)
                throw CodecError("richonline_classic_funds_card_deposit_unknown");
            const auto cash=target_after.cash/10,deposit=*target_after.deposit/10;
            if(source_after.cash>maximum-cash || *source_after.deposit>maximum-deposit)
                throw CodecError("richonline_classic_funds_card_balance_overflow");
            source_after.cash+=cash;*source_after.deposit+=deposit;
            target_after.cash-=cash;*target_after.deposit-=deposit;
        } else {
            const auto sum=static_cast<std::uint64_t>(source_after.cash)+target_after.cash;
            if(sum>maximum) throw CodecError("richonline_classic_funds_card_sum_overflow");
            // 670330使用32位加法和算术右移；非负范围奇数舍去余数，零余额不判破产。
            source_after.cash=target_after.cash=static_cast<std::uint32_t>(sum/2);
        }
        plan.funds_={{target,funds[target],target_after},{actor,funds[actor],source_after}};
    }
    append_le(plan.response_,use.opcode+0x4050,2);append_le(plan.response_,cards.game_id(),2);
    plan.response_.insert(plan.response_.end(),{use.inventory_slot,0});
    if(use.target) plan.response_.insert(plan.response_.end(),{*use.target,0});
    if(script) {
        bool consumed_call=false,snapshot_call=false,relations_call=false,invalid=false;
        std::size_t prepared=0;
        // Lua只得到当前事件的准备接口；C++复核每笔差额和完整响应，不暴露资金写接口。
        const auto reject=[&]() -> LuaValue {invalid=true;throw CodecError("lua_classic_funds_card_plan_invalid");};
        const LuaBindings bindings{
            {"card.prepare",[&](const LuaValue& args) {
                if(consumed_call || args!=LuaValue{{"card",card_id}} || !args.at("card").is_number_integer())
                    return reject();
                consumed_call=true;return LuaValue{{"slot",use.inventory_slot},{"bank",0}};
            }},
            {"game.snapshot",[&](const LuaValue&) {
                if(!consumed_call || snapshot_call) return reject();
                snapshot_call=true;auto actors=LuaValue::array();
                for(std::uint8_t slot=0;slot<active.size();++slot)
                    actors.push_back({{"slot",slot},{"active",active[slot]!=0},{"cash",funds[slot].funds.cash},
                        {"deposit",funds[slot].funds.deposit ? LuaValue(*funds[slot].funds.deposit):LuaValue{}}});
                return LuaValue{{"mode",0},{"actors",std::move(actors)}};
            }},
            {"funds.prepare",[&](const LuaValue& args) {
                if(!snapshot_call || relations_call || prepared>=plan.funds_.size()) return reject();
                const auto& expected=plan.funds_[prepared];
                LuaValue delta{{"actor",expected.actor}};
                if(use.opcode!=166) delta["cash"]=static_cast<std::int64_t>(expected.after.cash)-expected.before.funds.cash;
                if(use.opcode!=115) delta["deposit"]=static_cast<std::int64_t>(*expected.after.deposit)-*expected.before.funds.deposit;
                if(args!=delta || !std::ranges::all_of(args,[](const auto& value){return value.is_number_integer();}))
                    return reject();
                ++prepared;return LuaValue{};
            }},
            {"relations.break",[&](const LuaValue& args) {
                if(!use.target || relations_call || prepared!=plan.funds_.size() ||
                    args!=LuaValue{{"target",*use.target}} || !args.at("target").is_number_integer()) return reject();
                // 共享会话核验关系快照，并在账本/扣卡提交后无异常地解除这对同盟。
                relations_call=true;return LuaValue{};
            }}
        };
        const auto response=script->call("game.action",{{"payload",lua_bytes(packet)},{"opcode",use.opcode},
            {"map",std::string(cards.map_name())},{"actor",actor},{"calendar",calendar},
            {"game_id",cards.game_id()}},bindings);
        if(invalid || !consumed_call || !snapshot_call || prepared!=plan.funds_.size() ||
            relations_call!=use.target.has_value() || !response.is_array() || response.size()!=1 ||
            !response[0].is_string() || lua_bytes(response[0])!=plan.response_)
            throw CodecError("lua_classic_funds_card_response_invalid");
    }
    return plan;
}
bool commit_richonline_classic_funds_card(RichonlinePlayerCards& cards,RichonlineGameLedger& ledger,
    std::span<const std::uint8_t> active,const RichonlineClassicFundsCardPlan& plan) {
    const auto ready=[&]() noexcept {
        return &cards==plan.cards_ && &ledger==plan.ledger_ && cards.inventory()==plan.before_inventory_ &&
            std::ranges::equal(active,plan.active_);
    };
    if(!ready()) return false;
    return ledger.commit_batch(plan.funds_,[&]() noexcept {
        if(!ready()) return false;
        cards.commit_inventory(plan.after_inventory_);return true;
    });
}
}
