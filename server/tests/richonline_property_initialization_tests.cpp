#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_property_resources.hpp"

#include <algorithm>
#include <iostream>
#include <type_traits>

namespace {
using namespace richnet;
static_assert(!std::is_constructible_v<RichonlineBossProperty,const std::filesystem::path&,
    std::uint16_t,std::array<std::uint32_t,2>>,"property_runtime_requires_selected_stage");
void check(bool value,std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
void every_map_initial_state(const std::filesystem::path& root) {
    std::vector<std::string> names;
    for (unsigned chapter=1;chapter<=3;++chapter)
        for (unsigned stage=1;stage<=4;++stage)
            names.push_back("BS_"+std::to_string(chapter)+"_"+std::to_string(stage)+".emp");
    names.emplace_back("V_BS_1_1.emp");
    for (const auto& name:names) {
        const auto stage=load_richonline_boss_stage(root,name,name=="V_BS_1_1.emp" ? 2U : 0U);
        RichonlineBossProperty runtime(root,0x1234,{12000,150000},stage);
        const auto resource=load_richonline_property_resources(root,name);
        const auto world=runtime.combat_snapshot();
        check(world.buildings.size()==resource.properties.size(),"combat_snapshot_omitted_initial_property");
        for (const auto& initial:resource.properties) {
            check(runtime.price(initial.id)==initial.price && runtime.owner(initial.id)==initial.owner &&
                runtime.building(initial.id)==RichonlineBossProperty::Building{initial.kind,initial.level},
                "runtime_initial_state_diverged_from_selected_EMP");
            const auto building=std::find_if(world.buildings.begin(),world.buildings.end(),[&](const auto& p) {
                return p.property==static_cast<std::uint32_t>(initial.id);
            });
            check(building!=world.buildings.end() && building->kind==initial.kind && building->level==initial.level &&
                building->owner==initial.owner,"combat_initial_building_state_diverged");
        }
        check(runtime.cash()==std::array<std::uint32_t,2>{12000,150000},"initial_property_load_charged_ledger");
    }
}
void mismatched_stage_is_rejected(const std::filesystem::path& root) {
    const auto selected=load_richonline_boss_stage(root,"BS_2_1.emp");
    for (const auto field:{0,1,2}) {
        auto stage=selected;
        if (field==0) ++stage.width;
        else if (field==1) ++stage.height;
        else stage.mode=0;
        auto ledger=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{
            {12000,{},0,{}},{150000,{},0,{}}});
        try {
            RichonlineBossProperty runtime(root,0x1234,ledger,stage);
            throw std::runtime_error("mismatched_property_stage_accepted");
        } catch(const CodecError& error) {
            check(std::string_view(error.what())=="richonline_boss_property_stage_mismatch",
                "wrong_mismatched_property_stage_rejection");
        }
        check(ledger->snapshot(0).funds.cash==12000 && ledger->snapshot(1).funds.cash==150000,
            "mismatched_property_stage_mutated_ledger");
    }
}
void purchase_preserves_research_center(const std::filesystem::path& root) {
    const auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
    for (const auto actor:{std::uint8_t{0},std::uint8_t{1}}) {
        RichonlineBossProperty runtime(root,0x1234,{12000,150000},stage);
        const auto now=RichonlineBossProperty::Clock::time_point{};
        runtime.enable_human_decisions(std::chrono::milliseconds{5000},[&] { return now; });
        check(runtime.price(168)==100 && !runtime.owner(168) &&
            runtime.building(168)==RichonlineBossProperty::Building{13,1},"BS_1_1_initial_research_center_missing");
        const RichonlineLandingContext context{actor,183,33,168,3,actor==1,2,false};
        const auto landing=runtime.land(context);
        check(landing.has_value(),"prebuilt_unowned_landing_not_handled");
        if (actor==0) {
            check(landing->progress==RichonlineLandingProgress::await_event && landing->pending_opcode==0x20,
                "prebuilt_purchase_decision_not_pending");
            runtime.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0xaa,0xbb,0xcc});
        } else check(landing->progress==RichonlineLandingProgress::complete,"boss_prebuilt_purchase_did_not_complete");
        check(runtime.owner(168)==actor && runtime.building(168)==RichonlineBossProperty::Building{13,1},
            "prebuilt_purchase_cleared_existing_kind_or_level");
        check(runtime.cash()[actor]==(actor==0 ? 11900U : 149900U),"prebuilt_purchase_price_wrong");
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"NEW_resource_root_required");
        every_map_initial_state(argv[1]); mismatched_stage_is_rejected(argv[1]);
        purchase_preserves_research_center(argv[1]);
        std::cout<<"PASS NEW selected-map property constructors, combat initial snapshots and prebuilt purchase retention\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
