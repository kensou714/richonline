#include "richonline_boss_landing.hpp"
#include "richonline_boss_property.hpp"
#include "richonline_boss_shop.hpp"
#include "richonline_boss_stage.hpp"
#include <algorithm>
#include <iostream>
#include <set>

namespace {
using namespace richnet;
void check(bool value,const char* error) { if(!value) throw std::runtime_error(error); }
template<class F> void reject(F fn) { try { fn(); } catch(const CodecError&) { return; } throw std::runtime_error("invalid_control_landing_accepted"); }
RichonlineActorStatus control(unsigned which) {
    RichonlineActorStatus result;
    if(which==0) result.possession=7;
    else if(which==1) result.sleepwalking=2;
    else result.frozen=2;
    return result;
}
void completed(const RichonlineLandingResult& result,std::int16_t position) {
    Bytes stop{0x13,0x40,0x34,0x12}; append_le(stop,static_cast<std::uint16_t>(position),2);
    check(result.progress==RichonlineLandingProgress::complete && !result.pending_opcode &&
        result.messages==std::vector<Bytes>{stop},"controlled_landing_left_event_or_extra_response");
}
RichonlineLandingContext cell_context(const RichonlineRoadCell& cell,std::uint8_t actor=0) {
    const auto degree=std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](const auto& next){return next.has_value();});
    return {actor,cell.position,cell.static_type,cell.property_ref,3,actor==1,static_cast<std::uint8_t>(degree),false};
}
void special_preflight_and_components(const std::filesystem::path& root) {
    for(unsigned which=0;which<3;++which) {
        for(const auto kind:{std::int8_t{1},std::int8_t{5},std::int8_t{6},std::int8_t{7},std::int8_t{8},
            std::int8_t{10},std::int8_t{28},std::int8_t{41},std::int8_t{42}}) {
            RichonlineLandingContext context{0,117,kind,-1,3,false,2,false}; context.actor_status=control(which);
            const auto result=resolve_richonline_controlled_static_landing(0x1234,context);
            check(result.has_value(),"controlled_special_was_not_preflighted"); completed(*result,117);
            context.property_ref=216;
            check(!resolve_richonline_controlled_static_landing(0x1234,context),"property_charging_was_globally_skipped");
        }
        auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{100,1000,7,99},{100,1000,8,88}});
        RichonlineBossLandingState landing(0x1234,ledger);
        RichonlineLandingContext reward{0,117,5,-1,3,false,2,false}; reward.actor_status=control(which);
        const auto before=ledger->snapshot(0); landing.validate_landing(reward); completed(landing.land(reward),117);
        check(ledger->snapshot(0)==before,"controlled_ticket_square_credited_or_revised_ledger");
        const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
        RichonlineBossCards cards(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
        unsigned selections=0;
        RichonlineBossShop shop(root,cards,0x1234,ledger,[]{return RichonlineBossShop::Clock::time_point{};},
            {0xa5,0x5a},[&](std::size_t){++selections;return std::size_t{0};});
        auto context=reward; context.static_type=10;
        check(shop.validate_landing(context),"controlled_shop_rejected_valid_component_landing");
        const auto result=shop.land(context); check(result.has_value(),"controlled_shop_not_completed"); completed(*result,117);
        check(!shop.active() && !shop.poll() && selections==0 && ledger->snapshot(0)==before,"controlled_shop_opened_or_selected_stock");
        context.actor_slot=1; context.synthetic_actor=true;
        completed(resolve_richonline_empty_boss_landing(0x1234,context),117);
    }
    RichonlineLandingContext context{0,117,10,-1,3,false,2,false};
    check(!resolve_richonline_controlled_static_landing(0x1234,context),"ordinary_shop_silently_skipped");
    context.actor_status.turtle=2; context.actor_status.stay=2;
    check(!resolve_richonline_controlled_static_landing(0x1234,context),"turtle_stay_wrongly_controls_landing");
    context.actor_status.possession=7; context.occupied_by_other_actor=true;
    reject([&]{resolve_richonline_controlled_static_landing(0x1234,context);});
}
void properties_on_all_chapter_art(const std::filesystem::path& root) {
    std::set<std::int8_t> art;
    for(unsigned chapter=1;chapter<=3;++chapter) {
        const auto name="BS_"+std::to_string(chapter)+"_1.emp";
        const auto stage=load_richonline_boss_stage(root,name);
        const auto topology=load_richonline_road_topology(root/"Map"/name);
        RichonlineBossProperty property(root,0x1234,{1000000,1000000},stage);
        property.enable_human_decisions(std::chrono::seconds{5},[]{return RichonlineBossProperty::Clock::time_point{};});
        std::array<std::int8_t,10> skills{}; skills.fill(7); property.configure_construction(skills);
        for(const auto& cell:topology.cells()) {
            if(!cell.walkable || cell.property_ref<0) continue;
            auto context=cell_context(cell);
            if(property.owner(cell.property_ref)) continue;
            const auto before=property.combat_snapshot(); const auto cash=property.cash();
            context.actor_status=control(0);
            check(property.validate_landing(context),"chapter_property_artwork_not_accepted");
            const auto result=property.land(context); check(result.has_value(),"controlled_property_missing"); completed(*result,cell.position);
            check(property.cash()==cash && property.combat_snapshot().buildings==before.buildings && !property.poll(),"controlled_purchase_mutated_property");
            context.actor_slot=1; context.synthetic_actor=true; context.actor_status=control(1);
            const auto boss=property.land(context); check(boss.has_value(),"controlled_boss_property_missing"); completed(*boss,cell.position);
            context.actor_slot=0; context.synthetic_actor=false; context.actor_status={};
            const auto ordinary=property.land(context);
            check(ordinary && ordinary->progress==RichonlineLandingProgress::await_event && ordinary->pending_opcode==0x20,
                "ordinary_chapter_purchase_did_not_wait");
            property.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0,0,0});
            const auto purchased=property.combat_snapshot(); const auto paid=property.cash();
            context.actor_status=control(2);
            const auto owned=property.land(context); check(owned.has_value(),"controlled_owned_property_missing"); completed(*owned,cell.position);
            check(property.cash()==paid && property.combat_snapshot().buildings==purchased.buildings && !property.poll(),"controlled_owned_property_built_or_waited");
            context.static_type=static_cast<std::int8_t>(cell.static_type+1);
            check(!property.validate_landing(context),"fabricated_artwork_admitted");
            art.insert(cell.static_type);
        }
    }
    check(std::any_of(art.begin(),art.end(),[](auto n){return n>=33 && n<=36;}) &&
        std::any_of(art.begin(),art.end(),[](auto n){return n>=44 && n<=47;}) &&
        std::any_of(art.begin(),art.end(),[](auto n){return n>=37 && n<=40;}),"actual_chapter_art_ranges_not_exercised");
}
}
int main(int argc,char** argv) {
    try { const auto root=argc>1 ? argv[1] : "../Richonline";
        special_preflight_and_components(root); properties_on_all_chapter_art(root);
        std::cout<<"NEW controlled static/property continuations and chapter art tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
