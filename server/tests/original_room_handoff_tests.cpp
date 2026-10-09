#include "original_room_handoff_support.hpp"
#include <iostream>

namespace {
using namespace room_handoff_test;
void start_snapshot_and_playing_guards() {
    Fixture fixture; fixture.create(); const auto redirects=fixture.start();
    check(fixture.snapshots.size()==1,"provider invoked once"); const auto& snapshot=fixture.snapshots.front();
    check(snapshot.generation!=0 && snapshot.channel_id==2 && snapshot.game_id==0 && snapshot.owner==12,"room snapshot identity");
    check(snapshot.players.size()==2 && snapshot.players[0].user_id==12 && snapshot.players[0].slot==0 && snapshot.players[0].team==0 &&
        snapshot.players[1].user_id==25 && snapshot.players[1].slot==1 && snapshot.players[1].team==3,"snapshot membership/slot/team");
    for (const auto& player : snapshot.players) {
        auto expected=profile(player.user_id); put(expected,12,0); put(expected,44,player.team);
        check(player.profile==expected,"snapshot must retain complete real room profile and model");
    }
    auto expected=description(); put(expected,60,12); put(expected,64,0); put(expected,124,0);
    check(snapshot.description.wire==expected,"snapshot preserves opaque configuration");
    fixture.rooms.request(12,{5,{}}); fixture.rooms.request(25,{5,{}});
    for (const auto user : {12U,25U,39U}) check(fixture.rooms.drain(user).empty(),"duplicate ready cannot redirect twice");
    rejects([&] { fixture.rooms.request(39,{4,words({0,0,1})}); },"original_room_game_in_progress");
    auto config=words({0}); const auto body=description(); config.insert(config.end(),body.begin(),body.end());
    rejects([&] { fixture.rooms.request(12,{23,config}); },"original_room_game_in_progress");
    check(!fixture.host->status(snapshot.generation).admitted,"redirect does not prove admission");
    check(redirects[0].payload!=redirects[1].payload,"member credentials differ");
}
void provider_failure_and_minimum_players() {
    Fixture fixture; fixture.create(); fixture.fail=true;
    fixture.rooms.request(12,{5,{}}); fixture.rooms.request(25,{5,{}});
    for (const auto user : {12U,25U,39U}) {
        const auto frames=fixture.rooms.drain(user); check(frames.size()==4,"failed provider sends only ready transitions");
        check(frames[0].wire_type==13 && frames[1].wire_type==13 && frames[2].wire_type==96 && frames[2].payload==words({12,0}) &&
            frames[3].wire_type==96 && frames[3].payload==words({25,0}),"failed provider rollback atomic");
    }
    check(!fixture.rooms.ready(12) && !fixture.rooms.ready(25),"failure clears readiness");
    fixture.fail=false; fixture.start(); check(fixture.snapshots.size()==2,"provider retry remains usable");
    Fixture minimum; minimum.create(false,2); minimum.rooms.request(12,{5,{}});
    for (const auto user : {12U,25U,39U}) {
        const auto frames=minimum.rooms.drain(user); check(frames.size()==2 && frames[0].wire_type==13 && frames[1].wire_type==96 &&
            frames[1].payload==words({12,0}),"minimum population cancels ready");
    }
    check(minimum.snapshots.empty(),"underfilled room must not call provider");
}
void idle_expiry_and_pending_cancel() {
    Fixture fixture; fixture.create(); const auto redirects=fixture.start(); const auto old=echo(redirects[0],12);
    fixture.now+=std::chrono::milliseconds(100); recovered(fixture);
    check(!fixture.host->callbacks().authorize_admission(old),"timeout revokes old token");
    const auto retry=fixture.start(); check(fixture.snapshots[1].generation!=fixture.snapshots[0].generation,"retry generation differs");
    fixture.rooms.request(25,{60,{}}); recovered(fixture);
    check(!fixture.host->callbacks().authorize_admission(echo(retry[1],25)),"cancel revokes pending token");
    fixture.start(); check(fixture.snapshots.size()==3,"cancel leaves room restartable");
}
void active_close_and_stale_cleanup() {
    Fixture fixture; fixture.create(); const auto redirects=fixture.start();
    const auto old_generation=fixture.snapshots.back().generation;
    GameSession first(ClientVersion::legacy,fixture.host->callbacks()), second(ClientVersion::legacy,fixture.host->callbacks());
    first.feed(admission_packet(echo(redirects[0],12))); second.feed(admission_packet(echo(redirects[1],25)));
    first.finish(); removed(fixture);
    check(word(fixture.rooms.profile(12),12)==0xffffffffU && word(fixture.rooms.profile(25),12)==0xffffffffU,"active EOF removes membership");
    fixture.create(); const auto next=fixture.start(); const auto generation=fixture.snapshots.back().generation;
    check(generation!=old_generation && fixture.snapshots.back().game_id==0,"room ID reused with new generation");
    second.finish();
    rejects([&] { fixture.host->status(old_generation); },"original_game_host_generation_missing");
    for (const auto user : {12U,25U,39U}) check(fixture.rooms.drain(user).empty(),"old cleanup cannot remove new room");
    check(!fixture.host->finished(generation) && word(fixture.rooms.profile(12),12)==0,"new generation survives stale EOF");
    check(!fixture.host->callbacks().authorize_admission(echo(redirects[0],12)),"old generation cannot reenter");
    auto admitted=fixture.host->callbacks(); const auto admission=echo(next[0],12);
    check(admitted.authorize_admission(admission),"new generation token remains live"); admitted.admitted(admission);
}
void lobby_disconnect_closes_active_gate() {
    Fixture fixture; fixture.create(); const auto redirects=fixture.start();
    auto one=fixture.host->callbacks(), two=fixture.host->callbacks(); const auto a=echo(redirects[0],12), b=echo(redirects[1],25);
    check(one.authorize_admission(a) && two.authorize_admission(b),"both game peers authorized"); one.admitted(a); two.admitted(b);
    fixture.rooms.disconnect(12); removed(fixture,{25,39});
    rejects([&] { two.poll(b); },"original_game_host_match_closed");
    rejects([&] { fixture.host->status(fixture.snapshots.back().generation); },"original_game_host_generation_missing");
    check(fixture.closed==2,"lobby EOF cancels all active strategies once");
    one.disconnected(a); two.disconnected(b); check(fixture.closed==2,"late game cleanup stays idempotent");
}
}
int main() {
    try {
        start_snapshot_and_playing_guards(); provider_failure_and_minimum_players(); idle_expiry_and_pending_cancel();
        active_close_and_stale_cleanup(); lobby_disconnect_closes_active_gate();
        std::cout<<"PASS room handoff control lifecycle using synthetic startup strategies, not gameplay acceptance.\n"; return 0;
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
