#include "richonline_special_landings.hpp"
#include <limits>

namespace richnet {
namespace {
constexpr std::uint32_t merchant_tickets=25,merchant_cash=2000;
constexpr auto signed_max=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void check_funds(const RichonlineGameFunds& funds) {
    if(funds.cash>signed_max || funds.tickets>signed_max ||
        (funds.deposit && (*funds.deposit>signed_max || funds.cash>signed_max-*funds.deposit)))
        throw CodecError("richonline_special_landing_funds_out_of_range");
}
}
std::optional<RichonlinePreparedSpecialLanding> prepare_richonline_special_landing(std::uint16_t game,
    const RichonlineSpecialLandingContext& context,const RichonlineGameFundsSnapshot& funds) {
    const auto& cell=context.landing;
    if(cell.static_type!=57 && cell.static_type!=58) return {};
    if(cell.game_mode!=3 || cell.actor_slot>1 || cell.synthetic_actor!=(cell.actor_slot==1) || cell.position<0 ||
        cell.property_ref!=-1 || cell.road_degree==0 || cell.road_degree>4 ||
        (cell.occupied_by_other_actor && !cell.collision_resolved))
        throw CodecError("richonline_special_landing_context_invalid");
    check_funds(funds.funds);
    RichonlinePreparedSpecialLanding result;result.actor_=cell.actor_slot;result.status_=cell.actor_status;
    result.before_=funds;result.after_=funds.funds;
    Bytes stop;append_le(stop,0x4013,2);append_le(stop,game,2);
    append_le(stop,static_cast<std::uint16_t>(cell.position),2);result.messages_.push_back(std::move(stop));
    if(context.scripted_event_active) {result.outcome_=RichonlineSpecialOutcome::scripted_skip;return result;}
    if(cell.actor_status.possession==7 || cell.actor_status.sleepwalking || cell.actor_status.frozen)
        return result;
    if(cell.static_type==58) {
        result.outcome_=RichonlineSpecialOutcome::server_event_required;
        result.continuation_=RichonlineSpecialContinuation::awaiting_server_event;return result;
    }
    if(!cell.synthetic_actor && funds.funds.tickets<merchant_tickets) {
        result.outcome_=RichonlineSpecialOutcome::insufficient_tickets;return result;
    }
    const auto total=static_cast<std::uint64_t>(funds.funds.cash)+funds.funds.deposit.value_or(0);
    if(total>signed_max-merchant_cash) throw CodecError("richonline_special_landing_cash_overflow");
    result.after_.cash+=merchant_cash;
    if(!cell.synthetic_actor) result.after_.tickets-=merchant_tickets;
    result.outcome_=RichonlineSpecialOutcome::merchant_exchange;return result;
}
bool commit_richonline_special_landing(RichonlineGameLedger& ledger,RichonlinePreparedSpecialLanding& plan,
    const RichonlineActorStatus& status,const std::function<bool()>& authorize) {
    if(plan.continuation_!=RichonlineSpecialContinuation::property_phase2)
        throw CodecError("richonline_special_landing_server_event_response_required");
    if(!authorize) throw CodecError("richonline_special_landing_authorization_required");
    if(plan.committed_ || status!=plan.status_) return false;
    const std::array updates{RichonlineGameFundsUpdate{plan.actor_,plan.before_,plan.after_}};
    if(!ledger.commit_batch(updates,authorize)) return false;
    plan.committed_=true;return true;
}
}
