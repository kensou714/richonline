#include "richonline_ground_card_authority.hpp"
#include "original_map.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
RichonlineRoadTopology geometry(std::uint32_t width,std::uint32_t height,std::int16_t blocked) {
    const auto count=static_cast<std::size_t>(width)*height;
    OriginalEmp emp{3,width,height,{},{},Bytes(8+count*68,0xff),8,8+count*64,0,0};
    for (std::size_t i=0;i<count;++i)
        if (static_cast<std::int16_t>(i)!=blocked) emp.payload.at(8+64*i)=8;
    return richonline_road_topology(emp);
}
template<class Action> void rejects(Action action,const char* expected) {
    try { action(); } catch (const CodecError& error) {
        check(std::string_view(error.what())==expected,"wrong_rejection");return;
    }
    throw std::runtime_error("missing_rejection");
}
}
int main() {
    try {
        const RichonlineCombatRangePolicy policy{"server_manhattan_tile_radius",3,
            RichonlineProjectileCandidates::road_tiles};
        const auto board=geometry(5,3,7);
        auto first=make_richonline_ground_card_authority(board,2,policy);
        check(first(0,0,3) && first(1,0,11),"radius_boundary_rejected");
        check(!first(0,0,4) && !first(0,0,12),"radius_plus_one_allowed");
        check(!first(0,4,5),"row_wrap_treated_as_neighbor");
        check(!first(0,-1,0) && !first(0,0,-1) && !first(0,15,0) && !first(0,0,15),
            "invalid_position_allowed");
        check(!first(0,7,6) && !first(0,6,7),"blocked_road_allowed");
        check(!first(2,0,1) && !first(255,0,1),"foreign_actor_allowed");
        const auto second=make_richonline_ground_card_authority(geometry(3,3,1),1,
            RichonlineCombatRangePolicy{"server_manhattan_tile_radius",1,
                RichonlineProjectileCandidates::all_map_tiles});
        check(first(0,0,1) && !second(0,0,1),"room_road_sets_shared");
        check(!first(0,4,5) && second(0,4,5),"room_dimensions_shared");
        check(first(1,0,1) && !second(1,0,3),"room_actor_sets_shared");
        check(!make_richonline_ground_card_authority(board,2,{}),"absent_policy_enabled");
        rejects([&] { make_richonline_ground_card_authority(board,0,policy); },
            "richonline_ground_card_actor_count_invalid");
        rejects([&] { make_richonline_ground_card_authority(board,257,policy); },
            "richonline_ground_card_actor_count_invalid");
        for (const auto radius:{0,65}) {
            auto invalid=policy;invalid.manhattan_radius=static_cast<std::uint16_t>(radius);
            rejects([&] { make_richonline_ground_card_authority(board,2,invalid); },
                "richonline_ground_card_range_policy_invalid");
        }
        auto invalid=policy;invalid.name="client_camera";
        rejects([&] { make_richonline_ground_card_authority(board,2,invalid); },
            "richonline_ground_card_range_policy_invalid");
        std::cout<<"PASS per-room ground-card server range authorization\n";
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n';return 1; }
}
