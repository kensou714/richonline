#include "original_wealth.hpp"
#include <algorithm>
#include <limits>

namespace richnet {
namespace {
OriginalWealthContinuation continuation(OriginalWealthOrigin origin) {
    switch (origin) {
        case OriginalWealthOrigin::landing: return OriginalWealthContinuation::landing;
        case OriginalWealthOrigin::card: return OriginalWealthContinuation::card;
        case OriginalWealthOrigin::property: return OriginalWealthContinuation::property;
    }
    throw CodecError("original_wealth_origin_invalid");
}
void credit(OriginalFunds& funds, std::uint32_t amount) {
    if (amount > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-funds.cash)
        throw CodecError("original_wealth_cash_overflow");
    funds.cash += amount;
}
bool debit(OriginalFunds& funds, std::uint32_t amount) {
    if (funds.cash >= amount) funds.cash -= amount;
    else {
        const auto remainder = amount-funds.cash;
        funds.cash = 0;
        funds.deposit = remainder >= funds.deposit ? 0U : funds.deposit-remainder;
    }
    return funds.cash == 0 && funds.deposit == 0;
}
void validate(const OriginalWealthPending& pending, const OriginalWealthSnapshot& snapshot) {
    if (snapshot.context != pending.context || snapshot.actor != pending.actor)
        throw CodecError("original_wealth_snapshot_mismatch");
    if (snapshot.players.size() < 2 || snapshot.players.size() > 8 || pending.actor >= snapshot.players.size())
        throw CodecError("original_wealth_players_invalid");
    if (!snapshot.players[pending.actor].alive || snapshot.players[pending.actor].god != pending.god)
        throw CodecError("original_wealth_actor_mismatch");
    std::size_t alive = 0;
    for (const auto& player : snapshot.players) {
        if (player.alive) ++alive;
        for (const auto value : {player.funds.cash,player.funds.deposit,player.funds.tickets})
            if (value > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
                throw CodecError("original_wealth_funds_invalid");
    }
    if (alive < 2) throw CodecError("original_wealth_insufficient_active_players");
}
}
void OriginalWealthSettlement::begin(OriginalWealthPending pending) {
    if (pending_) throw CodecError("original_wealth_already_pending");
    if (pending.actor >= 8 || (pending.god != 0 && pending.god != 1))
        throw CodecError("original_wealth_pending_invalid");
    static_cast<void>(continuation(pending.origin));
    pending_ = pending;
}
OriginalWealthOutcome OriginalWealthSettlement::resolve(const OriginalWealthChoice& request,
    const OriginalWealthSnapshot& snapshot, std::int32_t amount) {
    if (!pending_ || awaiting_bankruptcy_) throw CodecError("original_wealth_choice_not_pending");
    if (request.context != pending_->context) throw CodecError("original_wealth_context_mismatch");
    if (request.action != 1) throw CodecError("original_wealth_action_invalid");
    if (amount < 0 || amount > 32767) throw CodecError("original_wealth_amount_invalid");
    validate(*pending_,snapshot);
    const auto actor = pending_->actor;
    const auto whole = static_cast<std::uint32_t>(amount);
    OriginalWealthOutcome outcome{snapshot.players,{},static_cast<std::int16_t>(amount),false,continuation(pending_->origin)};
    if (pending_->god == 0) {
        const auto enemy_count = std::count_if(snapshot.players.begin(),snapshot.players.end(),[&](const auto& player) {
            return player.alive && player.team != snapshot.players[actor].team;
        });
        const auto share = enemy_count == 0 ? 0U : whole/static_cast<std::uint32_t>(enemy_count);
        credit(outcome.players[actor].funds,whole);
        for (std::size_t slot = 0; slot < outcome.players.size(); ++slot)
            if (slot != actor && outcome.players[slot].alive && outcome.players[slot].team != outcome.players[actor].team &&
                debit(outcome.players[slot].funds,share)) outcome.bankrupt_slots.push_back(static_cast<std::uint8_t>(slot));
    } else {
        const auto alive_count = std::count_if(snapshot.players.begin(),snapshot.players.end(),[](const auto& player) { return player.alive; });
        const auto share = whole/static_cast<std::uint32_t>(alive_count-1);
        for (std::size_t slot = 0; slot < outcome.players.size(); ++slot)
            if (slot != actor && outcome.players[slot].alive) credit(outcome.players[slot].funds,share);
        if (debit(outcome.players[actor].funds,whole)) outcome.bankrupt_slots.push_back(actor);
    }
    outcome.bankruptcy_wait = !outcome.bankrupt_slots.empty();
    if (outcome.bankruptcy_wait) {
        outcome.continuation = OriginalWealthContinuation::bankruptcy;
        awaiting_bankruptcy_ = true;
    } else pending_.reset();
    return outcome;
}
OriginalWealthContinuation OriginalWealthSettlement::finish_bankruptcy(std::uint16_t context) {
    if (!pending_ || !awaiting_bankruptcy_) throw CodecError("original_wealth_bankruptcy_not_pending");
    if (context != pending_->context) throw CodecError("original_wealth_context_mismatch");
    const auto next = continuation(pending_->origin);
    pending_.reset();
    awaiting_bankruptcy_ = false;
    return next;
}
}
