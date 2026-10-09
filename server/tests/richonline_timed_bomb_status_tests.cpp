#include "richonline_timed_bomb.hpp"
#include <iostream>

int main() {
    using namespace richnet;
    try {
        RichonlineActorStatus before;before.timed_bomb=36;before.timed_bomb_owner=-1;
        before.possession=7;before.frozen=2;before.sleepwalking=3;before.safety_helmet_uses=19;
        auto ticks=before;richonline_status_finish_previous_turn(ticks);
        richonline_status_begin_active_turn(ticks);richonline_status_begin_combat_phase(ticks);
        if(ticks.timed_bomb!=36 || ticks.timed_bomb_owner!=-1 || ticks.safety_helmet_uses!=19)
            throw std::runtime_error("turn_clock_changed_carried_bomb_or_helmet_counter");
        const auto table=RichonlineChanceEventTable::parse("map\t16\t0\t0\t0\t0\t0\t,\ti\trecovered");
        const auto result=plan_richonline_chance_status(table,"map",0,7,{},before,{3,3},{false,{}},{0xab,0xcd});
        if(!result.removed_timed_bomb || !result.detached_possession || result.after.timed_bomb ||
            result.after.timed_bomb_owner || result.after.possession || result.after.safety_helmet_uses!=19 ||
            result.after.frozen!=2 || result.after.sleepwalking!=3 || before.timed_bomb!=36 ||
            before.timed_bomb_owner!=-1 || result.packet!=Bytes({0x96,0x40,7,0,0,0}))
            throw std::runtime_error("chance16_did_not_clear_pair_or_changed_unrelated_status");
        std::cout<<"PASS NEW chance16 paired bomb cleanup and independent turn/helmet clocks\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
