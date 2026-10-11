#include "richonline_rent_transfer.hpp"
#include "lua_wire.hpp"
#include <algorithm>
#include <bit>
#include <limits>

namespace richnet {
RichonlineRentTransferChoice decode_richonline_rent_transfer_choice(View request) {
    if(request.size()!=6 || read_le(request.first(2))!=0x76)
        throw CodecError("richonline_rent_transfer_request_invalid");
    const auto target=std::bit_cast<std::int8_t>(request[4]);
    // -2仅是7BC100内部自动查找参数，线上实际发送的是目标槽或-1。
    if(target< -1 || target>3) throw CodecError("richonline_rent_transfer_choice_invalid");
    return {static_cast<std::uint16_t>(read_le(request.subspan(2,2))),target,request[5]};
}
RichonlineRentTransferPlan plan_richonline_rent_transfer(const RichonlineRentTransferState& state,
    const RichonlineRentTransferChoice& choice,bool timed_out,std::shared_ptr<LuaServer> script) {
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    const auto count=state.funds.size();
    if(count<2 || count>4 || state.eligible.size()!=count || state.original_payer>=count ||
        state.recipient>=count || state.recipient==state.original_payer || state.amount<10000 ||
        state.amount>maximum || state.card_slot<0 || state.card_slot>=8 || choice.calendar!=state.calendar)
        throw CodecError("richonline_rent_transfer_context_invalid");
    for(const auto& snapshot:state.funds)
        if(!snapshot.funds.deposit || snapshot.funds.cash>maximum || *snapshot.funds.deposit>maximum)
            throw CodecError("richonline_rent_transfer_balance_unknown");
    const auto card_slot=static_cast<std::size_t>(state.card_slot);
    if(state.inventory[card_slot].card_id!=1056 || state.inventory[card_slot].count<=0)
        throw CodecError("richonline_rent_transfer_card_missing");
    const auto target=timed_out ? std::int8_t{-1} : choice.target;
    if(target< -1 || (target>=0 && (static_cast<std::size_t>(target)>=count ||
        target==state.original_payer || !state.eligible[static_cast<std::size_t>(target)])))
        throw CodecError("richonline_rent_transfer_target_ineligible");
    const auto payer=target<0 ? state.original_payer : static_cast<std::uint8_t>(target);
    const auto& source=state.funds[payer];
    const auto available=static_cast<std::uint64_t>(source.funds.cash)+*source.funds.deposit;
    if(available>maximum) throw CodecError("richonline_rent_transfer_total_unsupported");
    const auto charged=std::min(state.amount,static_cast<std::uint32_t>(available));
    const auto& recipient=state.funds[state.recipient];
    if(charged>maximum-*recipient.funds.deposit)
        throw CodecError("richonline_rent_transfer_recipient_overflow");
    auto credited=recipient.funds;*credited.deposit+=charged;
    auto payer_before=source;
    // UI允许选择地主。客户端先给地主存款，再从同一人现金/存款扣钱；
    // 不能把它简化成无资金操作，否则现金、存款和收入统计都会错位。
    if(payer==state.recipient && charged!=0) {
        if(recipient.revision==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_rent_transfer_revision_overflow");
        payer_before={credited,recipient.revision+1};
    }
    auto debited=payer_before.funds;
    const auto cash_paid=std::min(charged,debited.cash);
    debited.cash-=cash_paid;*debited.deposit-=charged-cash_paid;
    RichonlineRentTransferPlan plan{target,payer,charged,target>=0,debited.cash==0 && *debited.deposit==0,
        {{state.recipient,recipient,credited},{payer,payer_before,debited}},state.inventory,{}};
    if(plan.consume_card && --plan.inventory[card_slot].count==0) plan.inventory[card_slot]={};
    // 6712B0只读GmsvID和signed目标BYTE。+5并非已证实的响应字段，不回显请求padding。
    append_le(plan.response,0x40c6,2);append_le(plan.response,state.game_id,2);
    plan.response.push_back(static_cast<std::uint8_t>(target));
    if(script) {
        auto balances=LuaValue::array(),eligible=LuaValue::array();
        for(std::size_t index=0;index<count;++index) {
            balances.push_back({{"cash",state.funds[index].funds.cash},{"deposit",*state.funds[index].funds.deposit}});
            eligible.push_back(static_cast<bool>(state.eligible[index]));
        }
        const auto result=script->call("card.rent_transfer",{{"game_id",state.game_id},{"original_payer",state.original_payer},
            {"recipient",state.recipient},{"amount",state.amount},{"choice",choice.target},{"timed_out",timed_out},
            {"balances",std::move(balances)},{"eligible",std::move(eligible)}});
        const LuaValue expected{{"target",target},{"payer",payer},{"charged",charged},{"consume_card",plan.consume_card},
            {"bankrupt",plan.bankrupt},{"credited_deposit",*credited.deposit},{"payer_cash",debited.cash},
            {"payer_deposit",*debited.deposit},{"message",lua_bytes(View(plan.response))}};
        if(result!=expected) throw CodecError("lua_rent_transfer_plan_invalid");
        for(const auto* key:{"target","payer","charged","credited_deposit","payer_cash","payer_deposit"})
            if(!result.at(key).is_number_integer()) throw CodecError("lua_rent_transfer_integer_required");
    }
    return plan;
}
}
