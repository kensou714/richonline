#include "richonline_special_session.hpp"
#include "richonline_route.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
template<class F> void rejects(F fn) {
    try { fn(); } catch(const CodecError&) { return; }
    throw std::runtime_error("expected_rejection");
}
const RichonlineRoadCell& merchant_cell(const RichonlineRoadTopology& topology) {
    const auto found=std::find_if(topology.cells().begin(),topology.cells().end(),[](const auto& cell) {
        return cell.walkable && cell.static_type==57;
    });
    if(found==topology.cells().end()) throw std::runtime_error("real_map_has_no_static57");
    return *found;
}
RichonlineLandingContext context(const RichonlineRoadCell& cell,std::uint8_t actor=0) {
    const auto degree=std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& next){return next.has_value();});
    return {actor,cell.position,cell.static_type,cell.property_ref,3,actor==1,static_cast<std::uint8_t>(degree),false};
}
std::shared_ptr<RichonlineGameLedger> make_ledger(std::uint32_t human_tickets=30) {
    return std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1000,400,human_tickets,7},{1000,0,30,8}});
}
RichonlineMerchantSession::ScriptedStateReader initial_scripted_state() {
    // Fixture authority mirrors NEW7BAE60's explicit initial sentinel.
    return [](const RichonlineLandingContext&)->std::optional<std::int8_t>{return -1;};
}
void human_exchange(const RichonlineRoadTopology& topology,const RichonlineRoadCell& cell) {
    auto ledger=make_ledger();
    std::vector<std::pair<std::string,nlohmann::json>> logs;
    RichonlineMerchantSession session(topology,ledger,0x1234,9,"BS_3_1.emp",
        [&](const std::string& event,const nlohmann::json& fields){logs.emplace_back(event,fields);},initial_scripted_state());
    const auto landing=context(cell);
    check(session.validate_landing(landing),"real_human_merchant_rejected");
    const auto result=session.land(landing);
    check(result && result->progress==RichonlineLandingProgress::complete,"merchant_did_not_complete");
    Bytes expected;append_le(expected,0x4013,2);append_le(expected,0x1234,2);append_le(expected,static_cast<std::uint16_t>(cell.position),2);
    check(result->messages==std::vector<Bytes>{expected},"merchant_sent_extra_money_packet");
    check(ledger->snapshot(0).funds==RichonlineGameFunds{3000,400,5,7},"human_exchange_balance_or_other_fund_wrong");
    check(ledger->snapshot(0).revision==1,"human_exchange_not_committed_once");
    check(logs.size()==1 && logs[0].first=="richonline_merchant_landed" &&
        logs[0].second.at("room")==9 && logs[0].second.at("package")=="BS_3_1.emp" &&
        logs[0].second.at("actor_slot")==0 && logs[0].second.at("position")==cell.position &&
        logs[0].second.at("outcome")=="merchant_exchange" &&
        logs[0].second.at("cash_before")==1000 && logs[0].second.at("cash_after")==3000 &&
        logs[0].second.at("tickets_before")==30 && logs[0].second.at("tickets_after")==5 &&
        logs[0].second.at("game83830")==-1 && logs[0].second.at("scripted_event_active")==false &&
        logs[0].second.at("extra_money_packet")==false,"merchant_audit_log_incomplete");
    const auto after=ledger->snapshot(0);const auto insufficient=session.land(landing);
    check(insufficient && insufficient->messages==std::vector<Bytes>{expected} && ledger->snapshot(0)==after &&
        logs.size()==2 && logs.back().second.at("outcome")=="insufficient_tickets", "second_landing_invented_ticket_credit");
}
void no_exchange_paths(const RichonlineRoadTopology& topology,const RichonlineRoadCell& cell) {
    {
        auto ledger=make_ledger(24);RichonlineMerchantSession session(topology,ledger,3,4,"BS_3_1.emp",{},initial_scripted_state());
        const auto before=ledger->snapshot(0);const auto result=session.land(context(cell));
        check(result && result->messages.size()==1 && ledger->snapshot(0)==before,"insufficient_tickets_changed_state");
    }
    {
        auto ledger=make_ledger();RichonlineMerchantSession session(topology,ledger,3,4,"BS_3_1.emp",{},initial_scripted_state());
        const auto result=session.land(context(cell,1));
        check(result && result->messages.size()==1 && ledger->snapshot(1).funds==RichonlineGameFunds{3000,0,30,8},
            "synthetic_boss_paid_or_missed_reward");
    }
    for(unsigned control=0;control<3;++control) {
        auto ledger=make_ledger();RichonlineMerchantSession session(topology,ledger,3,4,"BS_3_1.emp",{},initial_scripted_state());
        auto landing=context(cell);if(control==0) landing.actor_status.possession=7;
        else if(control==1) landing.actor_status.sleepwalking=1;
        else landing.actor_status.frozen=1;
        const auto before=ledger->snapshot(0);const auto result=session.land(landing);
        check(result && result->messages.size()==1 && ledger->snapshot(0)==before,"controlled_actor_traded");
    }
    for(const std::int8_t raw:{std::int8_t{0},std::int8_t{1},std::int8_t{2}}) {
        auto ledger=make_ledger();RichonlineMerchantSession session(topology,ledger,3,4,"BS_3_1.emp",{},
            [raw](const RichonlineLandingContext&)->std::optional<std::int8_t>{return raw;});
        const auto before=ledger->snapshot(0);auto scripted=context(cell);
        const auto result=session.land(scripted);
        check(result && result->messages.size()==1 && ledger->snapshot(0)==before,"scripted_event_traded");
    }
}
void topology_gate(const RichonlineRoadTopology& topology,const RichonlineRoadCell& cell) {
    auto ledger=make_ledger();RichonlineMerchantSession session(topology,ledger,3,4,"BS_3_1.emp",{},initial_scripted_state());
    const auto other=std::find_if(topology.cells().begin(),topology.cells().end(),[](const auto& candidate){return candidate.static_type!=57;});
    check(other!=topology.cells().end(),"fixture_has_no_other_static");
    auto invalid=context(cell);invalid.position=other->position;
    rejects([&]{session.validate_landing(invalid);});
    invalid=context(cell);invalid.road_degree=static_cast<std::uint8_t>((invalid.road_degree%4U)+1U);
    rejects([&]{session.land(invalid);});
    invalid=context(cell);invalid.property_ref=0;
    rejects([&]{session.validate_landing(invalid);});
    invalid=context(cell);invalid.collision_resolved=false;invalid.occupied_by_other_actor=true;
    rejects([&]{session.land(invalid);});
    invalid=context(cell);invalid.static_type=58;
    check(!session.validate_landing(invalid),"merchant_adapter_claimed_server_event_static58");
}
void failed_logging_preserves_response(const RichonlineRoadTopology& topology,const RichonlineRoadCell& cell) {
    auto ledger=make_ledger();RichonlineMerchantSession session(topology,ledger,3,4,"BS_3_1.emp",
        [](const std::string&,const nlohmann::json&){throw std::runtime_error("diagnostic_sink_unavailable");},initial_scripted_state());
    const auto result=session.land(context(cell));
    check(result && result->messages.size()==1 && ledger->snapshot(0).funds==RichonlineGameFunds{3000,400,5,7},
        "failed_log_lost_response_or_commit");
}
void no_merchant_map_gate() {
    const auto topology=load_richonline_road_topology("../Richonline/Map/BS_1_1.emp");
    check(std::none_of(topology.cells().begin(),topology.cells().end(),[](const auto& cell){return cell.static_type==57;}),
        "BS_1_1_static_set_changed");
    const auto road=std::find_if(topology.cells().begin(),topology.cells().end(),[](const auto& cell){return cell.walkable;});
    check(road!=topology.cells().end(),"BS_1_1_has_no_road");
    RichonlineMerchantSession session(topology,make_ledger(),3,4,"BS_1_1.emp",{},initial_scripted_state());
    auto invented=context(*road);invented.static_type=57;
    rejects([&]{session.validate_landing(invented);});
}
void explicit_authority(const RichonlineRoadTopology& topology,const RichonlineRoadCell& cell) {
    auto ledger=make_ledger();const auto before=ledger->snapshot(0);unsigned logs=0;
    rejects([&]{RichonlineMerchantSession missing(topology,ledger,3,4,"BS_3_1.emp",{},{});});
    RichonlineMerchantSession unknown(topology,ledger,3,4,"BS_3_1.emp",
        [&](const std::string&,const nlohmann::json&){++logs;},
        [](const RichonlineLandingContext&)->std::optional<std::int8_t>{return {};});
    rejects([&]{unknown.validate_landing(context(cell));});
    rejects([&]{unknown.land(context(cell));});
    check(ledger->snapshot(0)==before && logs==0,"unknown_authority_mutated_or_reported_success");
    std::int8_t raw=-1;unsigned reads=0;
    RichonlineMerchantSession dynamic(topology,ledger,3,4,"BS_3_1.emp",{},
        [&](const RichonlineLandingContext& landing)->std::optional<std::int8_t>{
            check(landing.position==cell.position && landing.actor_slot==0,"authority_context_mismatch");
            ++reads;return raw;
        });
    check(dynamic.validate_landing(context(cell)),"initial_authority_rejected");
    raw=0;check(dynamic.land(context(cell)).has_value() && ledger->snapshot(0)==before && reads==2,
        "preflight_cached_inactive_authority");
    raw=-1;check(dynamic.land(context(cell)).has_value() && ledger->snapshot(0).funds.cash==3000 && reads==3,
        "authority_not_read_at_each_admitted_landing");
}
}
int main() {
    try {
        const auto topology=load_richonline_road_topology("../Richonline/Map/BS_3_1.emp");
        const auto& cell=merchant_cell(topology);
        human_exchange(topology,cell);no_exchange_paths(topology,cell);topology_gate(topology,cell);no_merchant_map_gate();
        failed_logging_preserves_response(topology,cell);
        explicit_authority(topology,cell);
        std::cout<<"PASS real BS_3_1 static57 session exchange, BS_1_1 map gate, controls, and audit log\n";
    } catch(const std::exception& error) {
        std::cerr<<"FAIL "<<error.what()<<'\n';return 1;
    }
}
