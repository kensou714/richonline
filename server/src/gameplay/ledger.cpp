#include "richonline_game_ledger.hpp"
#include <limits>

namespace richnet {
namespace {
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
std::uint64_t earned_after(std::uint64_t earned,const RichonlineGameFunds& before,const RichonlineGameFunds& after) {
    const auto previous=static_cast<std::uint64_t>(before.cash)+before.deposit.value_or(0);
    const auto next=static_cast<std::uint64_t>(after.cash)+after.deposit.value_or(0);
    const auto increase=next>previous?next-previous:0;
    if(increase>std::numeric_limits<std::uint64_t>::max()-earned)
        throw CodecError("richonline_game_ledger_earned_cash_overflow");
    return earned+increase;
}
void valid(const RichonlineGameFunds& funds) {
    if (funds.cash>maximum || (funds.deposit && *funds.deposit>maximum) || funds.tickets>maximum ||
        (funds.reserve && *funds.reserve>maximum))
        throw CodecError("richonline_game_ledger_balance_invalid");
}
std::uint32_t changed(std::uint32_t value,std::int64_t delta) {
    if (delta < -static_cast<std::int64_t>(value)) throw CodecError("richonline_game_ledger_insufficient");
    if (delta > static_cast<std::int64_t>(maximum-value)) throw CodecError("richonline_game_ledger_overflow");
    return static_cast<std::uint32_t>(static_cast<std::int64_t>(value)+delta);
}
std::optional<std::uint32_t> changed(std::optional<std::uint32_t> value,std::int64_t delta) {
    if (!value) {
        if (delta!=0) throw CodecError("richonline_game_ledger_balance_unknown");
        return {};
    }
    return changed(*value,delta);
}
}
RichonlineGameLedger::RichonlineGameLedger(std::vector<RichonlineGameFunds> initial) {
    if (initial.empty() || initial.size()>8) throw CodecError("richonline_game_ledger_actor_count_invalid");
    balances_.reserve(initial.size());
    earned_cash_.resize(initial.size());
    for (const auto& funds:initial) { valid(funds); balances_.push_back({funds,0}); }
}
RichonlineGameFundsSnapshot RichonlineGameLedger::snapshot(std::uint8_t actor) const {
    const std::lock_guard lock(mutex_);
    if (actor>=balances_.size()) throw CodecError("richonline_game_ledger_actor_invalid");
    return balances_[actor];
}
std::uint64_t RichonlineGameLedger::earned_cash(std::uint8_t actor) const {
    return income_snapshot(actor).earned_cash;
}
RichonlineGameIncomeSnapshot RichonlineGameLedger::income_snapshot(std::uint8_t actor) const {
    const std::lock_guard lock(mutex_);
    if(actor>=balances_.size())throw CodecError("richonline_game_ledger_actor_invalid");
    if(!balances_[actor].funds.deposit)throw CodecError("richonline_game_ledger_earned_cash_unavailable");
    return {earned_cash_[actor],balances_[actor].revision};
}
RichonlineGameFundsSnapshot RichonlineGameLedger::commit(std::uint8_t actor,
    const RichonlineGameFundsSnapshot& expected,const RichonlineGameFunds& updated) {
    const std::lock_guard lock(mutex_);
    if (actor>=balances_.size()) throw CodecError("richonline_game_ledger_actor_invalid");
    auto& current=balances_[actor];
    if (current!=expected) throw CodecError("richonline_game_ledger_conflict");
    valid(updated);
    if (current.funds.deposit.has_value()!=updated.deposit.has_value() ||
        current.funds.reserve.has_value()!=updated.reserve.has_value())
        throw CodecError("richonline_game_ledger_knowledge_change");
    if (current.funds==updated) return current;
    if (current.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_game_ledger_revision_exhausted");
    const auto earned=earned_after(earned_cash_[actor],current.funds,updated);
    current={updated,current.revision+1};
    earned_cash_[actor]=earned;
    return current;
}
RichonlineGameFundsSnapshot RichonlineGameLedger::adjust(std::uint8_t actor,
    const RichonlineGameFundsSnapshot& expected,const RichonlineGameFundsDelta& delta) {
    valid(expected.funds);
    const RichonlineGameFunds updated{changed(expected.funds.cash,delta.cash),changed(expected.funds.deposit,delta.deposit),
        changed(expected.funds.tickets,delta.tickets),changed(expected.funds.reserve,delta.reserve)};
    return commit(actor,expected,updated);
}
std::optional<RichonlineGameFundsSnapshot> RichonlineGameLedger::consume_reserve(std::uint8_t actor,
    std::uint32_t amount,const std::function<bool()>& authorize) {
    const std::lock_guard lock(mutex_);
    if(actor>=balances_.size())throw CodecError("richonline_game_ledger_actor_invalid");
    if(!authorize)throw CodecError("richonline_game_ledger_authorizer_missing");
    auto& current=balances_[actor];
    if(!current.funds.reserve)throw CodecError("richonline_game_ledger_balance_unknown");
    const auto after=changed(*current.funds.reserve,-static_cast<std::int64_t>(amount));
    if(amount!=0 && current.revision==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_game_ledger_revision_exhausted");
    if(!authorize())return {};
    if(amount!=0){current.funds.reserve=after;++current.revision;}
    return current;
}
bool RichonlineGameLedger::commit_batch(std::span<const RichonlineGameFundsUpdate> updates,
    const std::function<bool()>& authorize) {
    return commit_updates(updates,authorize,false);
}
bool RichonlineGameLedger::commit_sequence(std::span<const RichonlineGameFundsUpdate> updates,
    const std::function<bool()>& authorize) {
    return commit_updates(updates,authorize,true);
}
bool RichonlineGameLedger::commit_updates(std::span<const RichonlineGameFundsUpdate> updates,
    const std::function<bool()>& authorize,bool sequential) {
    const std::lock_guard lock(mutex_);
    if(updates.empty() || (!sequential && updates.size()>balances_.size()) || !authorize)
        throw CodecError("richonline_game_ledger_batch_invalid");
    std::array<bool,8> seen{};
    std::array<RichonlineGameFundsSnapshot,8> projected{};
    std::array<std::uint64_t,8> earnings{};
    for(std::size_t actor=0;actor<balances_.size();++actor) {
        projected[actor]=balances_[actor];earnings[actor]=earned_cash_[actor];
    }
    for(const auto& update:updates) {
        if(update.actor>=balances_.size() || (!sequential && seen[update.actor]))
            throw CodecError("richonline_game_ledger_batch_actor_invalid");
        seen[update.actor]=true;
        auto& current=projected[update.actor];
        if(current!=update.before) throw CodecError("richonline_game_ledger_conflict");
        valid(update.after);
        if(current.funds.deposit.has_value()!=update.after.deposit.has_value() ||
            current.funds.reserve.has_value()!=update.after.reserve.has_value())
            throw CodecError("richonline_game_ledger_knowledge_change");
        if(current.funds!=update.after && current.revision==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_game_ledger_revision_exhausted");
        earnings[update.actor]=earned_after(earnings[update.actor],current.funds,update.after);
        if(current.funds!=update.after) current={update.after,current.revision+1};
    }
    if(!authorize()) return false;
    for(std::size_t actor=0;actor<balances_.size();++actor) if(seen[actor]) {
        balances_[actor]=projected[actor];earned_cash_[actor]=earnings[actor];
    }
    return true;
}
}
