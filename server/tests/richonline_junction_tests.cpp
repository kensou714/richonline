#include "richonline_junction.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class F> void rejects(F action,const char* expected) {
    try { action(); } catch(const CodecError& error) {
        check(std::string(error.what())==expected,"unexpected_junction_error"); return;
    }
    throw std::runtime_error("expected_junction_rejection");
}
Bytes request(std::int8_t direction,std::uint16_t counter=0x4567) {
    return {0x34,0,static_cast<std::uint8_t>(counter),static_cast<std::uint8_t>(counter>>8),
        static_cast<std::uint8_t>(direction),0xcc};
}
void choices_drive_next_movement(const RichonlineRoadTopology& topology) {
    const auto now=RichonlineJunction::Clock::time_point{};
    for (const auto position:{std::int16_t{178},std::int16_t{189}}) {
        const auto& cell=topology.cell(position);
        for (std::uint8_t heading=0;heading<4;++heading) {
            // Given a real NEW junction reached with this heading, every UI
            // permitted choice must become the next route's first direction.
            if (!cell.neighbors[(heading+2U)%4U]) continue;
            for (std::uint8_t direction=0;direction<4;++direction) {
                RichonlineJunction junction(0xabcd);
                check(junction.begin(topology,{position,heading,0x4567},now),"actual_shop_junction_not_pending");
                const auto outcome=junction.decide(request(static_cast<std::int8_t>(direction)),now);
                const bool permitted=cell.neighbors[direction].has_value() && direction!=(heading+2U)%4U;
                if (permitted) {
                    check(outcome.response==Bytes({0x35,0x40,0xcd,0xab,direction}) && outcome.heading==direction,
                        "junction_choice_not_synchronized");
                    const auto route=build_richonline_route(topology,{position,outcome.heading,1,{}},{});
                    check(route.directions.front()==direction && route.landings.front()==*cell.neighbors[direction],
                        "chosen_direction_ignored_by_next_route");
                } else check(outcome.response.back()==0xff && outcome.heading==heading,
                    "blocked_or_reverse_choice_changed_heading");
                check(!junction.pending() && !junction.poll(now+std::chrono::seconds{7}),"completed_choice_repeated");
            }
        }
    }
}
void deadline_and_cancel_preserve_heading(const RichonlineRoadTopology& topology) {
    const auto now=RichonlineJunction::Clock::time_point{};
    for (const bool late_click:{false,true}) {
        RichonlineJunction junction(0x1234);
        check(junction.begin(topology,{178,0,0x4567},now),"junction_missing");
        check(!junction.poll(now+std::chrono::milliseconds{5999}),"junction_expired_early");
        const auto deadline=now+std::chrono::milliseconds{6000};
        const auto result=late_click ? junction.decide(request(0),deadline) : *junction.poll(deadline);
        check(result.response==Bytes({0x35,0x40,0x34,0x12,0xff}) && result.heading==0,
            "junction_timeout_did_not_close_and_preserve_heading");
        rejects([&]{junction.decide(request(0),deadline);},"richonline_junction_not_pending");
    }
    RichonlineJunction junction(1);
    check(!junction.begin(topology,{117,3,9},now) && !junction.pending(),"degree_two_created_false_wait");
    junction.begin(topology,{178,0,0x4567},now);
    rejects([&]{junction.begin(topology,{189,1,9},now);},"richonline_junction_already_pending");
    rejects([&]{junction.decide(request(0,0x4568),now);},"richonline_junction_counter_mismatch");
    check(junction.pending(),"bad_counter_retired_current_decision");
    const auto cancel=junction.decide(request(-1),now);
    check(cancel.heading==0 && cancel.response.back()==0xff,"explicit_cancel_not_preserved");
}
void wire_fields() {
    const auto decoded=decode_richonline_junction_request(request(-1));
    check(decoded.calendar_counter==0x4567 && decoded.direction==-1 && decoded.unassigned_padding==0xcc,
        "signed_choice_or_counter_field_wrong");
    auto malformed=request(0); malformed[0]=0x37;
    rejects([&]{decode_richonline_junction_request(malformed);},"richonline_junction_request_opcode");
    malformed=request(0); malformed.pop_back();
    rejects([&]{decode_richonline_junction_request(malformed);},"richonline_junction_request_size");
    for (const auto value:{std::int8_t{-2},std::int8_t{4}}) {
        rejects([&]{decode_richonline_junction_request(request(value));},"richonline_junction_direction_invalid");
        rejects([&]{encode_richonline_junction_response(1,value);},"richonline_junction_direction_invalid");
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");
        const auto topology=load_richonline_road_topology(std::filesystem::path(argv[1])/"Map"/"BS_1_1.emp");
        wire_fields(); choices_drive_next_movement(topology); deadline_and_cancel_preserve_heading(topology);
        std::cout<<"PASS NEW junction direction, actual map routing and deadline closure\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
