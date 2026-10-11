#include "richonline_special_session.hpp"
#include "diagnostic_log.hpp"
#include <algorithm>

namespace richnet {
namespace {
const char* outcome_name(RichonlineSpecialOutcome outcome) {
    switch(outcome) {
    case RichonlineSpecialOutcome::controlled_skip: return "controlled_skip";
    case RichonlineSpecialOutcome::scripted_skip: return "scripted_skip";
    case RichonlineSpecialOutcome::insufficient_tickets: return "insufficient_tickets";
    case RichonlineSpecialOutcome::merchant_exchange: return "merchant_exchange";
    case RichonlineSpecialOutcome::server_event_required: break;
    }
    throw CodecError("richonline_merchant_unexpected_outcome");
}
}
RichonlineMerchantSession::RichonlineMerchantSession(RichonlineRoadTopology topology,
    std::shared_ptr<RichonlineGameLedger> ledger,std::uint16_t game,std::uint16_t room,std::string package,ControlLog log,
    ScriptedStateReader read_scripted_state)
    :topology_(std::move(topology)),ledger_(std::move(ledger)),game_(game),room_(room),package_(std::move(package)),
     log_(nonthrowing_diagnostic_log(std::move(log))),read_scripted_state_(std::move(read_scripted_state)) {
    if(!ledger_ || ledger_->actor_count()!=2) throw CodecError("richonline_merchant_ledger_invalid");
    if(!read_scripted_state_) throw CodecError("richonline_merchant_scripted_authority_required");
}
std::optional<RichonlinePreparedSpecialLanding> RichonlineMerchantSession::prepare(
    const RichonlineLandingContext& context,std::int8_t& raw_scripted) const {
    if(context.static_type!=57) return {};
    if(context.position<0 || static_cast<std::size_t>(context.position)>=topology_.cells().size() || context.actor_slot>=2)
        throw CodecError("richonline_merchant_landing_resource_mismatch");
    const auto& cell=topology_.cell(context.position);
    const auto degree=std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& next){return next.has_value();});
    if(!cell.walkable || cell.static_type!=context.static_type || cell.property_ref!=context.property_ref || degree!=context.road_degree)
        throw CodecError("richonline_merchant_landing_resource_mismatch");
    const auto authority=read_scripted_state_(context);
    if(!authority) throw CodecError("richonline_merchant_scripted_authority_unknown");
    raw_scripted=*authority;
    return prepare_richonline_special_landing(game_,{context,raw_scripted!=-1},ledger_->snapshot(context.actor_slot));
}
bool RichonlineMerchantSession::validate_landing(const RichonlineLandingContext& context) const {
    std::int8_t raw_scripted=-1;
    return prepare(context,raw_scripted).has_value();
}
std::optional<RichonlineLandingResult> RichonlineMerchantSession::land(const RichonlineLandingContext& context) {
    std::int8_t raw_scripted=-1;
    auto prepared=prepare(context,raw_scripted);
    if(!prepared) return {};
    return commit(context,*prepared,raw_scripted);
}
RichonlineLandingResult RichonlineMerchantSession::commit(const RichonlineLandingContext& context,
    RichonlinePreparedSpecialLanding& prepared,std::int8_t raw_scripted) {
    if(context.actor_slot!=prepared.actor() || read_scripted_state_(context)!=std::optional{raw_scripted})
        throw CodecError("richonline_merchant_authority_changed");
    // Allocate both output and diagnostic before committing funds. Only the
    // nonthrowing sink executes afterward, so logging cannot lose a response.
    RichonlineLandingResult result{prepared.messages(),RichonlineLandingProgress::complete};
    nlohmann::json fields{{"room",room_},{"package",package_},{"actor_slot",context.actor_slot},
        {"position",context.position},{"static_type",context.static_type},{"synthetic",context.synthetic_actor},
        {"game83830",raw_scripted},{"scripted_event_active",raw_scripted!=-1},
        {"outcome",outcome_name(prepared.outcome())},{"cash_before",prepared.before().funds.cash},
        {"cash_after",prepared.after().cash},{"tickets_before",prepared.before().funds.tickets},
        {"tickets_after",prepared.after().tickets},{"continuation","property_phase2"},
        {"extra_money_packet",false},{"level","info"}};
    if(!commit_richonline_special_landing(*ledger_,prepared,context.actor_status,[]{return true;}))
        throw CodecError("richonline_merchant_state_changed");
    if(log_) log_("richonline_merchant_landed",fields);
    return result;
}
}
