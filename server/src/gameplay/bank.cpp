#include "richonline_game_bank.hpp"
#include "lua_wire.hpp"

#include <bit>
#include <limits>
#include <utility>

namespace richnet {
RichonlineGameBankPassRequest decode_richonline_game_bank_pass(View plain) {
    if (plain.size()!=6) throw CodecError("richonline_game_bank_pass_size");
    if (read_le(plain.first(2))!=0x28) throw CodecError("richonline_game_bank_pass_opcode");
    const auto position=std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(4,2))));
    if (position<0) throw CodecError("richonline_game_bank_position_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),position};
}
RichonlineGameBankRequest decode_richonline_game_bank_request(View plain) {
    if (plain.size()!=12) throw CodecError("richonline_game_bank_request_size");
    if (read_le(plain.first(2))!=0x27) throw CodecError("richonline_game_bank_request_opcode");
    const auto action=read_le(plain.subspan(4,2));
    if (action>2) throw CodecError("richonline_game_bank_action_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),static_cast<RichonlineGameBankAction>(action),
        {plain[6],plain[7]},std::bit_cast<std::int32_t>(read_le(plain.subspan(8,4)))};
}
RichonlineGameBank::RichonlineGameBank(std::uint16_t game_id,RichonlineGameBankWirePolicy policy,Now now,
    std::shared_ptr<LuaServer> script)
    : game_id_(game_id),policy_(policy),now_(std::move(now)),script_(std::move(script)) {
    if (!now_) throw CodecError("richonline_game_bank_clock_required");
}
RichonlineGameBankResult RichonlineGameBank::begin(const RichonlineGameBankEntry& entry) {
    if (pending_) throw CodecError("richonline_game_bank_already_pending");
    if (entry.position<0) throw CodecError("richonline_game_bank_position_invalid");
    if (entry.actor_slot>=8) throw CodecError("richonline_game_bank_actor_invalid");
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if (entry.balance.cash>maximum || entry.balance.deposit>maximum)
        throw CodecError("richonline_game_bank_balance_invalid");
    std::uint8_t intermediate;
    switch (entry.visit) {
    case RichonlineGameBankVisit::passing: intermediate=1; break;
    case RichonlineGameBankVisit::landing: intermediate=0; break;
    default: throw CodecError("richonline_game_bank_visit_invalid");
    }
    Bytes admission;
    append_le(admission,0x4018,2); append_le(admission,game_id_,2);
    append_le(admission,static_cast<std::uint16_t>(entry.position),2);
    admission.push_back(intermediate); admission.push_back(policy_.admission_padding);
    if(script_) {
        const auto message=script_->call("bank.open",{{"game_id",game_id_},{"position",entry.position},
            {"passing",intermediate!=0},{"padding",policy_.admission_padding}});
        if(!message.is_string() || message!=lua_bytes(View(admission)))
            throw CodecError("lua_bank_admission_invalid");
        admission=lua_bytes(message);
    }
    if (entry.synthetic_actor) {
        // 显式模拟器策略：BOSS 不交易；先同步 4018 标志，再由 402A 原路径继续。
        auto result=transaction(entry,{entry.calendar_counter,RichonlineGameBankAction::exit,{},0},false);
        result.messages.insert(result.messages.begin(),std::move(admission));
        return result;
    }
    // Lua异常时不打开银行；校验后才启动与客户端UI一致的八秒等待。
    pending_=Pending{entry,now_()+std::chrono::milliseconds{8000}};
    return {{std::move(admission)},entry,entry.balance,
        RichonlineGameBankContinuation::await_choice,RichonlineGameBankOutcome::opened};
}
RichonlineGameBankResult RichonlineGameBank::transaction(const RichonlineGameBankEntry& entry,
    const RichonlineGameBankRequest& request,bool timed_out) const {
    // C++保留资金守恒与协议边界；Lua独立计算决策，必须和本次受认证快照一致。
    auto action=RichonlineGameBankAction::exit;
    std::uint32_t amount=0;
    auto outcome=RichonlineGameBankOutcome::exited;
    const char* reason="exited";
    if(entry.synthetic_actor) {outcome=RichonlineGameBankOutcome::synthetic_exit;reason="synthetic_exit";}
    else if(timed_out) {outcome=RichonlineGameBankOutcome::timed_out;reason="timed_out";}
    else if(request.action!=RichonlineGameBankAction::exit) {
        const auto source=request.action==RichonlineGameBankAction::deposit ? entry.balance.cash : entry.balance.deposit;
        const auto destination=request.action==RichonlineGameBankAction::deposit ? entry.balance.deposit : entry.balance.cash;
        constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
        if(request.amount<=0) {outcome=RichonlineGameBankOutcome::rejected_amount;reason="rejected_amount";}
        else if(static_cast<std::uint32_t>(request.amount)>source) {
            outcome=RichonlineGameBankOutcome::insufficient_funds;reason="insufficient_funds";
        } else if(static_cast<std::uint32_t>(request.amount)>maximum-destination) {
            outcome=RichonlineGameBankOutcome::destination_limit;reason="destination_limit";
        } else {
            action=request.action;amount=static_cast<std::uint32_t>(request.amount);
            outcome=RichonlineGameBankOutcome::transferred;reason="transferred";
        }
    }
    auto after=entry.balance;
    switch (action) {
    case RichonlineGameBankAction::deposit: after.cash-=amount; after.deposit+=amount; break;
    case RichonlineGameBankAction::withdraw: after.deposit-=amount; after.cash+=amount; break;
    case RichonlineGameBankAction::exit: amount=0; break;
    }
    Bytes response;
    append_le(response,0x402a,2); append_le(response,game_id_,2);
    append_le(response,static_cast<std::uint16_t>(action),2);
    response.insert(response.end(),policy_.transaction_padding.begin(),policy_.transaction_padding.end());
    append_le(response,amount,4);
    if(script_) {
        const auto plan=script_->call("bank.transaction",{{"game_id",game_id_},
            {"action",static_cast<std::uint16_t>(request.action)},{"amount",request.amount},
            {"cash",entry.balance.cash},{"deposit",entry.balance.deposit},
            {"synthetic",entry.synthetic_actor},{"timed_out",timed_out},{"padding",policy_.transaction_padding}});
        const LuaValue expected{{"action",static_cast<std::uint16_t>(action)},{"amount",amount},
            {"cash",after.cash},{"deposit",after.deposit},{"outcome",reason},{"message",lua_bytes(View(response))}};
        if(plan!=expected) throw CodecError("lua_bank_transaction_invalid");
        response=lua_bytes(plan.at("message"));
    }
    RichonlineGameBankResult result{{std::move(response)},entry,after,
        entry.visit==RichonlineGameBankVisit::passing ? RichonlineGameBankContinuation::resume_movement :
            RichonlineGameBankContinuation::continue_landing,outcome};
    return result;
}
RichonlineGameBankResult RichonlineGameBank::handle(View plain) {
    const auto request=decode_richonline_game_bank_request(plain);
    if (!pending_) throw CodecError("richonline_game_bank_not_pending");
    if (request.calendar_counter!=pending_->entry.calendar_counter)
        throw CodecError("richonline_game_bank_counter_mismatch");
    // 无专用失败包证据。无效交易采用已证实的退出分支，保留余额并关闭等待。
    // 客户端“取全部”在 7BBE60 发送前已替换为实际正数；线上 amount0 不代表取全部。
    auto result=transaction(pending_->entry,request,now_()>=pending_->deadline);
    pending_.reset();
    return result;
}
std::optional<RichonlineGameBankResult> RichonlineGameBank::poll() {
    if (!pending_ || now_()<pending_->deadline) return {};
    auto result=transaction(pending_->entry,
        {pending_->entry.calendar_counter,RichonlineGameBankAction::exit,{},0},true);
    pending_.reset();
    return result;
}
}
