#include "richonline_portal_landing.hpp"
#include "original_map.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,std::string_view reason) { if(!value) throw std::runtime_error(std::string(reason)); }
template<class F> void rejects(F action,std::string_view reason) {
    try { action(); } catch(const CodecError& error) { check(error.what()==reason,error.what()); return; }
    throw std::runtime_error("expected_portal_landing_rejection");
}
RichonlineLandingContext context(const RichonlineRoadTopology& topology,std::int16_t position,std::uint8_t actor) {
    const auto& cell=topology.cell(position);
    const auto degree=std::count_if(cell.neighbors.begin(),cell.neighbors.end(),
        [](const auto& next) { return next.has_value(); });
    return {actor,position,cell.static_type,cell.property_ref,3,actor==1,
        static_cast<std::uint8_t>(degree),false,{},false};
}
void actual_pairs(const std::filesystem::path& root) {
    struct Map { const char* name; std::int8_t type; std::array<std::int16_t,2> positions; };
    constexpr std::array maps{
        Map{"BS_3_1.emp",28,{125,146}},Map{"BS_3_3.emp",28,{197,236}},
        Map{"BS_3_4.emp",28,{92,230}},Map{"BS_3_3.emp",61,{105,226}},
        Map{"BS_3_4.emp",61,{135,236}},Map{"V_BS_1_1.emp",61,{105,229}}};
    for(const auto& map:maps) {
        const auto emp=load_original_emp(root/"Map"/map.name);
        const auto topology=richonline_road_topology(emp);
        const auto offset=map.type==28 ? 64U : 80U;
        std::array<std::int16_t,2> source_pair{};
        for(std::size_t i=0;i<source_pair.size();++i) {
            const auto x=read_le(View(emp.payload).subspan(emp.tail_offset+offset+8U*i,4));
            const auto y=read_le(View(emp.payload).subspan(emp.tail_offset+offset+4U+8U*i,4));
            source_pair[i]=static_cast<std::int16_t>(y*emp.width+x);
        }
        check(source_pair==map.positions,"map_portal_tail_pair_changed");
        const std::optional pair{source_pair};
        for(std::uint8_t actor=0;actor<2;++actor) for(std::size_t i=0;i<2;++i) {
            auto input=context(topology,source_pair[i],actor);
            const auto plan=plan_richonline_portal_landing(0x1234,topology,pair,input,false);
            check(plan && plan->expected.position==source_pair[i] &&
                plan->authoritative_position==source_pair[1U-i] &&
                plan->continuation==RichonlinePortalContinuation::awaiting_server_continuation &&
                !plan->expects_client_request(),"portal_landing_continuation_wrong");
            check(plan->confirmation==Bytes({0x13,0x40,0x34,0x12,
                static_cast<std::uint8_t>(source_pair[i]),0}),"portal_entry_not_confirmed_exactly_once");
            if(map.type==28) check(!topology.portal_destination(source_pair[i]),"static28_became_midroute_portal");
            for(int gate=0;gate<4;++gate) {
                input.actor_status={};
                if(gate==0) input.actor_status.possession=7;
                if(gate==1) input.actor_status.sleepwalking=1;
                if(gate==2) input.actor_status.frozen=1;
                const auto skipped=plan_richonline_portal_landing(0x1234,topology,pair,input,gate==3);
                check(skipped && skipped->authoritative_position==input.position &&
                    skipped->continuation==RichonlinePortalContinuation::property_phase2,
                    "controlled_or_scripted_portal_should_continue_phase2");
            }
        }
        auto input=context(topology,source_pair[0],0);
        rejects([&] { plan_richonline_portal_landing(1,topology,{},input,false); },
            "richonline_portal_landing_pair_missing");
        const std::optional duplicate{std::array{source_pair[0],source_pair[0]}};
        rejects([&] { plan_richonline_portal_landing(1,topology,duplicate,input,false); },
            "richonline_portal_landing_pair_invalid");
        const std::optional wrong{std::array{source_pair[0],std::int16_t{0}}};
        rejects([&] { plan_richonline_portal_landing(1,topology,wrong,input,false); },
            "richonline_portal_landing_pair_invalid");
        input.static_type=8;
        rejects([&] { plan_richonline_portal_landing(1,topology,pair,input,false); },
            "richonline_portal_landing_source_mismatch");
        input=context(topology,source_pair[0],0);input.occupied_by_other_actor=true;
        rejects([&] { plan_richonline_portal_landing(1,topology,pair,input,false); },
            "richonline_portal_landing_context_invalid");
        input.collision_resolved=true;
        check(plan_richonline_portal_landing(1,topology,pair,input,false).has_value(),
            "resolved_collision_portal_rejected");
        for(int gate=0;gate<4;++gate) {
            input=context(topology,source_pair[0],0);
            if(gate==0) input.actor_slot=2;
            if(gate==1) input.synthetic_actor=true;
            if(gate==2) input.game_mode=2;
            if(gate==3) ++input.road_degree;
            rejects([&] { plan_richonline_portal_landing(1,topology,pair,input,false); },
                "richonline_portal_landing_context_invalid");
        }
        input=context(topology,source_pair[0],0);++input.property_ref;
        rejects([&] { plan_richonline_portal_landing(1,topology,pair,input,false); },
            "richonline_portal_landing_source_mismatch");
        for(const auto& cell:topology.cells()) {
            if(cell.walkable && cell.static_type!=28 && cell.static_type!=61) {
                input=context(topology,cell.position,0);
                check(!plan_richonline_portal_landing(1,topology,pair,input,false),
                    "nonportal_landing_claimed");
                break;
            }
        }
    }
}
void wide_position() {
    OriginalEmp emp{};emp.width=2;emp.height=130;
    emp.terrain_offset=8;emp.tile_types_offset=8+260U*64U;
    emp.payload.resize(emp.tile_types_offset+260U*4U);
    std::fill_n(emp.payload.begin(),8,0xff);
    for(std::size_t position=0;position<260;++position) {
        emp.payload[emp.terrain_offset+position*64U]=0xff;
        std::fill_n(emp.payload.begin()+static_cast<std::ptrdiff_t>(emp.terrain_offset+position*64U+56U),4,0xff);
    }
    for(const auto position:{256U,258U}) {
        emp.payload[emp.terrain_offset+position*64U]=0;
        emp.payload[emp.tile_types_offset+position*4U]=28;
    }
    const auto topology=richonline_road_topology(emp);
    const std::optional pair{std::array<std::int16_t,2>{256,258}};
    const auto plan=plan_richonline_portal_landing(0xabcd,topology,pair,context(topology,256,0),false);
    check(plan && plan->confirmation==Bytes({0x13,0x40,0xcd,0xab,0x00,0x01}) &&
        plan->authoritative_position==258,"portal_position_word_truncated");
}
}
int main(int argc,char** argv) {
    try { check(argc==2,"NEW_resource_root_required");actual_pairs(argv[1]);wide_position();
        std::cout<<"PASS NEW static28/61 exact landing pairs, status gates, entry-only4013 and no mid-route28 transport\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n';return 1; }
}
