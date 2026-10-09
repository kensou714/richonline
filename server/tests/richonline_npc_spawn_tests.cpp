#include "richonline_npc_spawn.hpp"
#include <iostream>
#include <set>

namespace {
using namespace richnet;
void check(bool value,const char* error) { if(!value) throw std::runtime_error(error); }
template<class F> void reject(F fn) {
    try { fn(); } catch(const CodecError&) { return; }
    throw std::runtime_error("invalid_operation_accepted");
}
void drop_to(RichonlineGroundObjects& ground,std::size_t remaining) {
    for(const auto& [position,object]:ground.snapshot().objects) {
        if(ground.snapshot().objects.size()<=remaining) break;
        check(ground.consume(position,object),"pickup_failed");
    }
}
void spawn_and_wire() {
    const auto policy=RichonlineNpcSpawnPolicy::user_requested(0x71,0x81,0x79,0x89);
    RichonlineGroundObjects ground({0,1,2,3,4,5,6,7,8,9});
    ground.place(3,{12,2,3}); ground.place(7,{13,5,6});
    RichonlineNpcSpawner spawner(0x1234,policy,100);
    const auto initialized=spawner.initialize(ground);
    check(initialized.messages.size()==5 && initialized.unmet_target==0,"initial_population_wrong");
    const auto initial=ground.snapshot(); std::set<std::int8_t> gods; std::size_t chests=0;
    for(const auto& [position,object]:initial.objects) {
        if(object.npc>=0 && object.npc<8) {
            check(position!=3 && position!=7 && gods.insert(object.npc).second,"god_collision");
            check(object.byte7==0x71 && object.byte8==0x81,"god_fields_not_explicit");
        }
        if(object.npc==9) ++chests;
    }
    check(gods.size()==4 && chests==1 && initial.objects.at(3)==RichonlineGroundObject{12,2,3},"mine_overwritten");
    check(encode_richonline_npc_spawn401c(0x1234,231,{3,0xa5,0x5a})==
        Bytes({0x1c,0x40,0x34,0x12,231,0,3,0xa5,0x5a}),"spawn_wire_wrong");
    reject([] { encode_richonline_npc_spawn401c(1,2,{26,3,4}); });
    reject([&] { ground.place(3,{9,0,0}); });
    check(!ground.consume(3,{12,2,2}) && ground.snapshot()==initial,"mismatched_pickup_mutated");
    for(std::uint64_t i=1;i<=6;++i) check(spawner.finish_round(ground,i).messages.empty(),"max_population_exceeded");
    reject([&] { spawner.initialize(ground); });
    reject([&] { spawner.finish_round(ground,8); });
    reject([&] { spawner.finish_round(ground,5); });
}
void refill_and_duplicate() {
    const auto policy=RichonlineNpcSpawnPolicy::user_requested(11,12,13,14);
    RichonlineGroundObjects first({0,1,2,3,4,5,6,7}),second({0,1,2,3,4,5,6,7});
    RichonlineNpcSpawner a(1,policy,77),b(1,policy,77);
    a.initialize(first); b.initialize(second); drop_to(first,2); drop_to(second,2);
    for(std::uint64_t round=1;round<=6;++round) {
        const auto x=a.finish_round(first,round); const auto y=b.finish_round(second,round);
        check(x.messages==y.messages && first.snapshot()==second.snapshot(),"duplicate_advanced_rng");
        check(x.messages.size()==(round%3==0 ? 1U:0U),"refresh_not_every_three_rounds");
        const auto snapshot=first.snapshot(); const auto duplicate=a.finish_round(first,round);
        check(duplicate.duplicate && duplicate.messages.empty() && first.snapshot()==snapshot,"duplicate_mutated_ground");
    }
    drop_to(first,0); check(a.replenish_minimum(first).messages.size()==2,"minimum_not_restored");
    check(a.replenish_minimum(first).messages.empty(),"refill_not_idempotent");
    const auto before=first.snapshot(); std::int16_t free_position=0;
    while(before.objects.contains(free_position)) ++free_position;
    first.place(free_position,{12,1,2});
    check(!first.commit(before,before.objects) && first.snapshot().objects.contains(free_position),"stale_snapshot_accepted");
}
void blocked_and_small_maps() {
    const auto policy=RichonlineNpcSpawnPolicy::user_requested(1,2,3,4);
    RichonlineGroundObjects ground({3}); ground.place(3,{12,1,3});
    RichonlineNpcSpawner spawn(1,policy,100);
    check(spawn.initialize(ground).unmet_target==5,"full_map_did_not_report_deficit");
    check(spawn.finish_round(ground,1).unmet_target==2,"full_map_minimum_not_reported");
    check(spawn.replenish_minimum(ground).unmet_target==2,"full_map_refill_not_reported");
    check(ground.snapshot().objects.at(3).npc==12,"full_map_mine_changed");
    RichonlineGroundObjects empty({}); RichonlineNpcSpawner none(1,policy,1);
    check(none.initialize(empty).unmet_target==5,"empty_map_not_bounded");
    reject([] { RichonlineGroundObjects invalid({1,1}); });
}
void possession_clock() {
    RichonlineActorStatus status; status.possession=3; status.sleepwalking=2; status.timed_bomb=3;
    RichonlinePossessionClock clock{3,5,{}};
    for(std::uint64_t turn=1;turn<=5;++turn) {
        const auto result=tick_richonline_possession(clock,status,turn);
        check(result.clock.turns==5-turn && result.expired.has_value()==(turn==5),"possession_wrong_duration");
        check(result.status.sleepwalking==2 && result.status.timed_bomb==3,"expiry_changed_unrelated_status");
        clock=result.clock; status=result.status;
        const auto duplicate=tick_richonline_possession(clock,status,turn);
        check(duplicate.duplicate && duplicate.clock.turns==clock.turns && !duplicate.expired,"duplicate_expired_again");
    }
    check(!status.possession && !clock.npc,"possession_not_cleared");
    reject([&] { tick_richonline_possession(clock,status,4); });
    status.possession=0;
    reject([&] { tick_richonline_possession(clock,status,6); });
}
void constrained_pool() {
    auto policy=RichonlineNpcSpawnPolicy::user_requested(1,2,3,4);
    policy.refresh_chests=false;
    reject([&] { RichonlineNpcSpawner invalid(1,policy,1); });
    policy.initial_gods=2; policy.initial_chests=0; policy.god_pool={0,1,3};
    RichonlineGroundObjects ground({0,1,2,3,4,5}); RichonlineNpcSpawner spawn(1,policy,10);
    check(spawn.initialize(ground).messages.size()==2,"restricted_initial_wrong");
    for(std::uint64_t round=1;round<=6;++round) {
        const auto result=spawn.finish_round(ground,round);
        if(round==6) check(result.unmet_target==1,"exhausted_pool_did_not_report_deficit");
    }
    for(const auto& [position,object]:ground.snapshot().objects) {
        (void)position; check(object.npc==0 || object.npc==1 || object.npc==3,"disabled_chest_was_spawned");
    }
}
}
int main() {
    try { spawn_and_wire(); refill_and_duplicate(); blocked_and_small_maps(); possession_clock(); constrained_pool();
        std::cout<<"NEW NPC spawn, occupancy and own-turn expiration tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
