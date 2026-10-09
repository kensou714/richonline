#include "richonline_investment.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <set>
#include <utility>

namespace richnet {
namespace {
constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
void validate_funds(const RichonlineGameFundsSnapshot& funds) {
    if(funds.funds.cash>maximum || (funds.funds.deposit &&
        (*funds.funds.deposit>maximum || funds.funds.cash>maximum-*funds.funds.deposit)))
        throw CodecError("richonline_investment_funds_invalid");
}
RichonlineInvestmentContinuation continued(RichonlineInvestmentVisit visit,bool paused) {
    if(visit==RichonlineInvestmentVisit::landing) return RichonlineInvestmentContinuation::continue_landing;
    return paused ? RichonlineInvestmentContinuation::resume_movement : RichonlineInvestmentContinuation::continue_movement;
}
}
RichonlineInvestmentRules make_richonline_investment_rules(const RichonlineRoadTopology& topology,
    std::uint32_t base,std::uint32_t reward) {
    RichonlineInvestmentRules rules{base,reward,{}};
    for(const auto& cell:topology.cells()) {
        if(cell.static_type!=67) continue;
        if(!cell.walkable) throw CodecError("richonline_investment_point_not_walkable");
        rules.positions.push_back(cell.position);
    }
    if(rules.positions.size()>9) throw CodecError("richonline_investment_point_limit");
    if(base>maximum || reward>maximum) throw CodecError("richonline_investment_rules_amount_invalid");
    return rules;
}
RichonlineInvestmentRules make_richonline_investment_rules(const RichonlineRoadTopology& topology,
    const RichonlineBossStage& stage) {
    const bool active=std::any_of(topology.cells().begin(),topology.cells().end(),
        [](const auto& cell){return cell.static_type==67;});
    if(active && (!stage.invest_base || !stage.invest_return))
        throw CodecError("richonline_investment_resource_fields_missing");
    if(stage.width!=topology.width() || stage.height!=topology.height())
        throw CodecError("richonline_investment_map_metadata_mismatch");
    return make_richonline_investment_rules(topology,stage.invest_base.value_or(0),stage.invest_return.value_or(0));
}
RichonlineInvestmentPassRequest decode_richonline_investment_pass(View plain) {
    if(plain.size()!=6) throw CodecError("richonline_investment_pass_size");
    if(read_le(plain.first(2))!=0x2a) throw CodecError("richonline_investment_pass_opcode");
    const auto position=std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(4,2))));
    if(position<0) throw CodecError("richonline_investment_position_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),position};
}
RichonlineInvestmentRequest decode_richonline_investment_request(View plain) {
    if(plain.size()!=6) throw CodecError("richonline_investment_request_size");
    if(read_le(plain.first(2))!=0x2b) throw CodecError("richonline_investment_request_opcode");
    if(plain[4]>1) throw CodecError("richonline_investment_decision_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),plain[4]==1,plain[5]};
}
RichonlineInvestment::RichonlineInvestment(std::uint16_t game_id,RichonlineInvestmentRules rules,
    std::shared_ptr<RichonlineGameLedger> ledger,std::uint8_t opaque,Now now)
    : game_id_(game_id),rules_(std::move(rules)),ledger_(std::move(ledger)),
      admission_opaque7_(opaque),now_(std::move(now)) {
    if(!ledger_ || ledger_->actor_count()==0 || ledger_->actor_count()>8)
        throw CodecError("richonline_investment_ledger_invalid");
    if(!now_) throw CodecError("richonline_investment_clock_required");
    if(rules_.invest_base>maximum || rules_.invest_return>maximum)
        throw CodecError("richonline_investment_rules_amount_invalid");
    if(rules_.positions.size()>9) throw CodecError("richonline_investment_point_limit");
    std::set<std::int16_t> positions;
    for(const auto position:rules_.positions)
        if(position<0 || !positions.insert(position).second)
            throw CodecError("richonline_investment_rules_position_invalid");
}
RichonlineInvestmentState RichonlineInvestment::state(std::uint8_t actor) const {
    if(actor>=ledger_->actor_count()) throw CodecError("richonline_investment_actor_invalid");
    return states_[actor];
}
RichonlineInvestmentResult RichonlineInvestment::begin(const RichonlineInvestmentEntry& entry) {
    if(pending_) throw CodecError("richonline_investment_already_pending");
    if(entry.actor_slot>=ledger_->actor_count()) throw CodecError("richonline_investment_actor_invalid");
    if(entry.visit!=RichonlineInvestmentVisit::passing && entry.visit!=RichonlineInvestmentVisit::landing)
        throw CodecError("richonline_investment_visit_invalid");
    const auto position=std::find(rules_.positions.begin(),rules_.positions.end(),entry.position);
    if(position==rules_.positions.end()) throw CodecError("richonline_investment_position_invalid");
    const auto index=static_cast<std::size_t>(position-rules_.positions.begin());
    const auto marks=states_[entry.actor_slot];
    const auto funds=ledger_->snapshot(entry.actor_slot); validate_funds(funds);
    RichonlineInvestmentResult result{{},entry,marks,marks,funds,funds,continued(entry.visit,false),
        RichonlineInvestmentOutcome::static_effect_skipped};
    if(!entry.client_static_effect_allowed) return result;
    if(std::all_of(marks.collected.begin(),marks.collected.begin()+static_cast<std::ptrdiff_t>(rules_.positions.size()),
            [](bool value){return value;})) {
        const auto deposit=funds.funds.deposit.value_or(0);
        if(rules_.invest_return>maximum-deposit-funds.funds.cash)
            throw CodecError("richonline_investment_reward_overflow");
        if(marks.revision==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_investment_revision_overflow");
        auto updated=funds.funds; updated.cash+=rules_.invest_return;
        result.after.collected={}; ++result.after.revision;
        result.outcome=RichonlineInvestmentOutcome::collection_reward;
        // All throwing work precedes the ledger CAS. Following success, the
        // fixed-size marks assignment cannot throw or leave a half commit.
        if(updated!=funds.funds) result.funds_after=ledger_->commit(entry.actor_slot,funds,updated);
        states_[entry.actor_slot]=result.after;
        return result;
    }
    if(marks.collected[index]) { result.outcome=RichonlineInvestmentOutcome::already_collected; return result; }
    if(funds.funds.cash<=rules_.invest_base) { result.outcome=RichonlineInvestmentOutcome::insufficient_cash; return result; }
    Bytes admission; append_le(admission,0x4012,2); append_le(admission,game_id_,2);
    append_le(admission,static_cast<std::uint16_t>(entry.position),2);
    admission.push_back(static_cast<std::uint8_t>(entry.visit==RichonlineInvestmentVisit::passing));
    admission.push_back(admission_opaque7_);
    result.messages.push_back(admission);
    const auto deadline=now_()+std::chrono::milliseconds{8000};
    pending_=Pending{entry,marks,funds,index,deadline};
    if(entry.synthetic_actor) {
        // Named emulator policy: synthesized actor declines, through the same
        // proven flag-setting and completion handlers as a player's decision.
        auto done=finish(false,RichonlineInvestmentOutcome::synthetic_decline);
        done.messages.insert(done.messages.begin(),std::move(admission)); return done;
    }
    result.continuation=RichonlineInvestmentContinuation::await_choice;
    result.outcome=RichonlineInvestmentOutcome::opened;
    return result;
}
RichonlineInvestmentResult RichonlineInvestment::finish(bool accept,RichonlineInvestmentOutcome outcome) {
    if(!pending_) throw CodecError("richonline_investment_not_pending");
    const auto pending=*pending_;
    if(states_[pending.entry.actor_slot]!=pending.state)
        throw CodecError("richonline_investment_collection_changed");
    if(ledger_->snapshot(pending.entry.actor_slot)!=pending.funds)
        throw CodecError("richonline_investment_funds_changed");
    RichonlineInvestmentResult result{{},pending.entry,pending.state,pending.state,pending.funds,pending.funds,
        continued(pending.entry.visit,true),outcome};
    Bytes response; append_le(response,0x4040,2); append_le(response,game_id_,2);
    response.push_back(static_cast<std::uint8_t>(accept)); result.messages.push_back(std::move(response));
    if(accept) {
        if(pending.funds.funds.cash<=rules_.invest_base || pending.state.collected[pending.position_index])
            throw CodecError("richonline_investment_purchase_precondition_changed");
        if(pending.state.revision==std::numeric_limits<std::uint64_t>::max())
            throw CodecError("richonline_investment_revision_overflow");
        auto funds=pending.funds.funds; funds.cash-=rules_.invest_base;
        result.after.collected[pending.position_index]=true; ++result.after.revision;
        if(funds!=pending.funds.funds) result.funds_after=ledger_->commit(pending.entry.actor_slot,pending.funds,funds);
        states_[pending.entry.actor_slot]=result.after;
    }
    pending_.reset(); return result;
}
RichonlineInvestmentResult RichonlineInvestment::handle(View plain) {
    const auto request=decode_richonline_investment_request(plain);
    if(!pending_) throw CodecError("richonline_investment_not_pending");
    if(request.calendar_counter!=pending_->entry.calendar_counter)
        throw CodecError("richonline_investment_counter_mismatch");
    if(now_()>=pending_->deadline) return finish(false,RichonlineInvestmentOutcome::timed_out);
    return finish(request.accept,request.accept ? RichonlineInvestmentOutcome::purchased : RichonlineInvestmentOutcome::declined);
}
std::optional<RichonlineInvestmentResult> RichonlineInvestment::poll() {
    if(!pending_ || now_()<pending_->deadline) return {};
    // Explicit deterministic server policy; the original client autoplay uses
    // 85% acceptance and is not evidence of a historical server timeout rule.
    return finish(false,RichonlineInvestmentOutcome::timed_out);
}
}
