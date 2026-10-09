#include "richonline_boss_property.hpp"
#include "richonline_boss_cards.hpp"
#include "richonline_boss_stage.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
RichonlineLandingContext context(bool boss) { return {static_cast<std::uint8_t>(boss ? 1 : 0),232,33,216,3,boss,2,false}; }
void completes_without_rent(RichonlineBossProperty& properties,bool boss) {
    const auto before=properties.cash();
    const auto owner=properties.owner(216);
    const auto building=properties.building(216);
    const auto result=properties.land(context(boss));
    check(result && result->progress==RichonlineLandingProgress::complete && !result->pending_opcode &&
        result->messages==std::vector<Bytes>{{0x13,0x40,0x34,0x12,232,0}},"opponent_property_not_completed_with_only_stop");
    check(properties.cash()==before && properties.owner(216)==owner &&
        properties.building(216)->kind==building->kind && properties.building(216)->level==building->level,
        "boss_mode_opponent_property_invented_rent_or_mutated_building");
    check(!properties.poll(),"opponent_property_left_pending_decision");
}
void player_visits_boss_properties(const std::filesystem::path& root) {
    RichonlineBossProperty properties(root,0x1234,{1,100000},load_richonline_boss_stage(root,"BS_1_1.emp"));
    properties.enable_human_decisions(std::chrono::seconds{5},[]{ return RichonlineBossProperty::Clock::time_point{}; });
    properties.land(context(true));
    completes_without_rent(properties,false);
    for (int level=1;level<=5;++level) {
        properties.land(context(true));
        completes_without_rent(properties,false);
    }
    auto occupied=context(false); occupied.occupied_by_other_actor=true;
    check(!properties.land(occupied),"cooccupancy_combat_was_silently_skipped");
}
void boss_visits_licensed_player_buildings(const std::filesystem::path& root) {
    const auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    for (const std::int8_t kind : {std::int8_t{14},std::int8_t{16}}) {
        auto stage=load_richonline_boss_stage(root,"BS_1_1.emp");
        stage.scenario_caps.at(static_cast<std::size_t>(kind-11))=5;
        const auto construction=RichonlineConstructionResources::load(root,stage);
        RichonlineBossProperty properties(root,0x1234,{20000,1},stage);
        properties.enable_human_decisions(std::chrono::seconds{5},[]{ return RichonlineBossProperty::Clock::time_point{}; });
        auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0,0}});
        RichonlineChanceInventory inventory{};
        inventory[0]={construction.licence_ids.at(static_cast<std::size_t>(kind-11)),1};
        cards->commit_inventory(inventory);
        std::array<std::int8_t,10> skills{}; skills.fill(7);
        properties.configure_construction(skills,cards);
        properties.land(context(false));
        properties.decide(Bytes{0x20,0,7,0,0,0,0,0,1,0,0,0});
        completes_without_rent(properties,true);
        properties.land(context(false));
        properties.decide(Bytes{0x37,0,7,0,static_cast<std::uint8_t>(kind),0xaa});
        check(properties.building(216)->kind==kind,"licensed_build_setup_failed");
        if (kind==16) {
            const auto before=properties.cash();
            check(!properties.land(context(true)) && properties.cash()==before,
                "unimplemented_opponent_deity_effect_was_silently_skipped");
        } else completes_without_rent(properties,true);
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_path_required");
        const std::filesystem::path root(argv[1]);
        player_visits_boss_properties(root);
        boss_visits_licensed_player_buildings(root);
        std::cout << "PASS NEW BOSS opponent property no-rent phase and unresolved-effect boundaries\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
