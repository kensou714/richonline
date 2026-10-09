#include "richonline_lobby_vote.hpp"
#include "richonline_room_directory.hpp"

#include <algorithm>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
using Vote=RichonlineLobbyVote;
using Deliveries=std::vector<RichonlineRoomDispatch>;
const auto now=Vote::Time{}+std::chrono::seconds(100);
void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
template<class Action> void rejects(Action action,std::string_view expected) {
    try { action(); } catch(const CodecError& error) {
        if(error.what()!=expected) throw std::runtime_error(std::string("wrong rejection: ")+error.what()+" expected "+std::string(expected));
        return;
    }
    throw std::runtime_error("expected rejection missing");
}
Bytes words(std::initializer_list<std::uint32_t> values) {
    Bytes out;for(const auto value:values) append_le(out,value,4);return out;
}
void put(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for(std::size_t i=0;i<4;++i) bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
Frame nested(std::uint32_t type,Bytes payload) {
    const auto length=static_cast<std::uint32_t>(payload.size()+8);
    auto bytes=words({length,0,type,length});bytes.insert(bytes.end(),payload.begin(),payload.end());
    return {39,std::move(bytes)};
}
Frame kick(std::uint32_t proposer=10,std::uint32_t target=20,std::uint32_t room=1) {
    auto payload=words({proposer,room,target});payload.resize(44);payload[12]='x';
    return nested(27,std::move(payload));
}
Bytes description() {
    Bytes bytes(216);bytes[0]='R';put(bytes,32,0xc0);put(bytes,40,4);put(bytes,44,4);
    put(bytes,48,0xffffffffU);put(bytes,60,0xffffffffU);put(bytes,64,0xffffffffU);
    put(bytes,68,2);put(bytes,72,4);put(bytes,120,88);put(bytes,124,1);
    const std::string name="BS_1_1.emp";std::copy(name.begin(),name.end(),bytes.begin()+128);
    return bytes;
}
Frame map_vote(std::uint32_t owner=10) {
    auto bytes=description();put(bytes,32,0x40);put(bytes,60,owner);put(bytes,64,0);bytes[133]='2';
    auto payload=words({1});payload.insert(payload.end(),bytes.begin(),bytes.end());return nested(23,std::move(payload));
}
void codec_contracts() {
    const auto proposal=decode_richonline_vote39(kick());
    check(proposal.room==1 && proposal.kick_proposer==10 && proposal.kick_target==20,"kick identity");
    const auto prompt=encode_richonline_vote_prompt74(10,proposal);
    auto expected=words({10,27,52,0,27,52,10,1,20});expected.resize(68);expected[36]='x';
    check(prompt.wire_type==74 && prompt.payload==expected,"74 exact nested kick payload");
    check(encode_richonline_vote_started75(27).payload==words({27}),"75 inner type");
    check(encode_richonline_vote_result80(10,1,2,3).payload==words({10,1,2,3}),"80 counts layout");
    const auto map=decode_richonline_vote39(map_vote());
    check(map.map_description && map.map_description->extension.size()==88 && map.room==1,"map decode");
    for(const auto offset:{0U,4U,12U}) {
        auto bad=kick();bad.payload[offset]^=1;
        rejects([&]{decode_richonline_vote39(bad);},"richonline_vote39_nested_header");
    }
    auto bad=kick();put(bad.payload,8,9);
    rejects([&]{decode_richonline_vote39(bad);},"richonline_vote_inner_type");
    bad=kick();std::fill(bad.payload.begin()+28,bad.payload.end(),0x61);
    rejects([&]{decode_richonline_vote39(bad);},"richonline_vote39_reason_unterminated");
    rejects([]{decode_richonline_vote39({39,Bytes(15)});},"richonline_vote39_shape");
    rejects([]{decode_richonline_vote40({40,words({10,27,3})});},"richonline_vote40_choice");
    rejects([]{decode_richonline_vote40({40,Bytes(8)});},"richonline_vote40_shape");
    for(std::uint32_t choice=0;choice<3;++choice)
        check(static_cast<std::uint32_t>(decode_richonline_vote40({40,words({10,23,choice})}).choice)==choice,"choice mapping");
}
void state_machine() {
    const RichonlineVoteScope scope{2,1,10,{{100,10},{200,20},{300,30}},false};
    const auto proposal=decode_richonline_vote39(kick());
    Vote vote;
    check(!vote.begin(scope,100,proposal,now) && vote.electorate().size()==2,"proposer implicit agreement");
    rejects([&]{vote.begin(scope,100,proposal,now);},"richonline_vote_already_active");
    rejects([&]{vote.reply(scope,999,{10,27,RichonlineVoteChoice::agree},now);},"richonline_vote_voter_not_member");
    auto foreign=scope;foreign.channel=1;
    rejects([&]{vote.reply(foreign,200,{10,27,RichonlineVoteChoice::agree},now);},"richonline_vote_reply_scope_mismatch");
    rejects([&]{vote.reply(scope,200,{20,27,RichonlineVoteChoice::agree},now);},"richonline_vote_reply_proposal_mismatch");
    check(!vote.reply(scope,200,{10,27,RichonlineVoteChoice::oppose},now),"early finish");
    rejects([&]{vote.reply(scope,200,{10,27,RichonlineVoteChoice::agree},now);},"richonline_vote_duplicate_reply");
    auto finished=vote.reply(scope,300,{10,27,RichonlineVoteChoice::abstain},now);
    check(finished && !finished->approved() && finished->agree==1 && finished->oppose==1 && finished->abstain==1,"tie declined");
    check(!vote.active() && !vote.poll(scope,now+Vote::duration),"resolution exactly once");
    rejects([&]{vote.reply(scope,300,{10,27,RichonlineVoteChoice::agree},now);},"richonline_vote_not_active");
    vote.begin(scope,100,proposal,now);
    check(!vote.poll(scope,now+Vote::duration-std::chrono::milliseconds(1)),"early timeout");
    finished=vote.reply(scope,200,{10,27,RichonlineVoteChoice::oppose},now+Vote::duration);
    check(finished && finished->reason==RichonlineVoteEnd::timeout && finished->approved() && finished->agree==1 && finished->abstain==2,"deadline excludes late ballot");
    for(unsigned change=0;change<4;++change) {
        vote.begin(scope,100,proposal,now);
        vote.reply(scope,200,{10,27,RichonlineVoteChoice::agree},now);
        auto changed=scope;
        if(change==0) changed.owner=20;
        if(change==1) changed.participants[2].connection=301;
        if(change==2) changed.participants.pop_back();
        if(change==3) changed.game_pending=true;
        finished=vote.poll(changed,now);
        check(finished && !finished->approved() && finished->agree==0 && finished->oppose==0 && finished->abstain==3,"changed scope voids ballots");
    }
    vote.begin(scope,100,proposal,now);
    auto reordered=scope;std::reverse(reordered.participants.begin(),reordered.participants.end());
    check(!vote.poll(reordered,now),"order does not change membership");
    check(vote.cancel()->reason==RichonlineVoteEnd::room_changed && !vote.cancel(),"cancel once");
    auto pending=scope;pending.game_pending=true;
    rejects([&]{vote.begin(pending,100,proposal,now);},"richonline_vote_during_game");
    rejects([&]{vote.begin(scope,100,decode_richonline_vote39(kick(20)),now);},"richonline_vote_proposer_mismatch");
    rejects([&]{vote.begin(scope,100,decode_richonline_vote39(kick(10,10)),now);},"richonline_vote_kick_self");
    rejects([&]{vote.begin(scope,100,decode_richonline_vote39(kick(10,40)),now);},"richonline_vote_target_not_member");
    auto solo=scope;solo.participants.resize(1);
    finished=vote.begin(solo,100,decode_richonline_vote39(map_vote()),now);
    check(finished && finished->approved() && finished->agree==1,"single member map vote");
}
struct Fixture {
    RichonlineRoomDirectory rooms{{9,8}};
    explicit Fixture(unsigned members=3) {
        for(std::uint32_t id=1;id<=4;++id) enter(id,id*10);
        rooms.receive(1,10,{3,description()},now);
        for(std::uint32_t id=2;id<=members;++id) rooms.receive(id,id*10,{4,words({1,id-1,1})},now);
    }
    Deliveries enter(std::uint64_t connection,std::uint32_t actor) {
        auto profile=Bytes(272);put(profile,0,actor);return rooms.enter(connection,actor,{7,profile});
    }
    Deliveries reply(std::uint64_t connection,std::uint32_t proposer,std::uint32_t type,std::uint32_t choice) {
        return rooms.receive(connection,static_cast<std::uint32_t>(connection*10),{40,words({proposer,type,choice})},now);
    }
};
std::size_t count(const Deliveries& frames,std::uint32_t type) {
    return static_cast<std::size_t>(std::count_if(frames.begin(),frames.end(),[type](const auto& d){return d.frame.wire_type==type;}));
}
void results(const Deliveries& frames,Bytes expected,std::size_t recipients) {
    check(count(frames,80)==recipients,"result recipient count");
    for(const auto& d:frames) if(d.frame.wire_type==80) check(d.frame.payload==expected,"result counts");
}
void directory_map_and_kick() {
    Fixture f;
    const auto proposal=map_vote();
    const auto started=f.rooms.receive(2,20,proposal,now);
    check(started.size()==3 && started[0].recipient==2 && started[0].frame.wire_type==75 && count(started,74)==2,"nonowner proposal recipients");
    for(const auto& d:started) check(d.recipient!=4,"spectator cannot vote");
    rejects([&]{f.reply(4,20,23,0);},"richonline_room_peer_not_in_room");
    check(f.reply(1,20,23,0).empty(),"incomplete ballot");
    const auto accepted=f.reply(3,20,23,1);
    results(accepted,words({20,2,1,0}),3);
    check(count(accepted,26)==4,"map applied for all observers");
    const auto inner=decode_richonline_vote39(proposal).inner;
    for(const auto& d:accepted) if(d.frame.wire_type==26) check(d.frame.payload==inner.payload,"approved map exact payload");
    const auto late=f.enter(5,50);
    const auto room=std::find_if(late.begin(),late.end(),[](const auto& d){return d.frame.wire_type==5;});
    check(room!=late.end() && room->frame.payload[136+5]=='2',"late snapshot uses approved map");
    f.rooms.receive(2,20,kick(20,10),now);
    f.reply(1,20,27,1);
    const auto kicked=f.reply(3,20,27,0);
    results(kicked,words({20,2,1,0}),3);
    check(count(kicked,27)==5 && !f.rooms.room_key(1) && f.rooms.peer_count(1)==2,"owner kicked by vote");
    const auto expected=words({20,20,1,10});
    for(const auto& d:kicked) if(d.frame.wire_type==27)
        check(std::equal(expected.begin(),expected.end(),d.frame.payload.begin()),"kick transfers owner and retains proposer");
    const auto profile=f.rooms.current_profile(1,10);
    check(read_le(View(profile.payload).subspan(12,4))==0xffffffffU && read_le(View(profile.payload).subspan(44,4))==0xfffffffeU,"kicked profile location");
    f.rooms.receive(2,20,{23,decode_richonline_vote39(map_vote(20)).inner.payload},now);
}
void directory_lifecycle() {
    for(unsigned mutation=0;mutation<9;++mutation) {
        Fixture f;f.rooms.receive(1,10,map_vote(),now);f.reply(2,10,23,0);
        Deliveries changed;
        if(mutation==0) changed=f.rooms.receive(4,40,{4,words({1,3,1})},now);
        if(mutation==1) changed=f.rooms.disconnect(3);
        if(mutation==2) changed=f.rooms.receive(3,30,{6,words({1})},now);
        if(mutation==3) changed=f.rooms.receive(2,20,{5,{}},now);
        if(mutation==4) changed=f.rooms.receive(1,10,{23,decode_richonline_vote39(map_vote()).inner.payload},now);
        if(mutation==5) changed=f.rooms.receive(2,20,{9,words({2})},now);
        if(mutation==6) changed=f.rooms.select_character(2,8,[]{});
        if(mutation==7) changed=f.rooms.receive(1,10,{27,decode_richonline_vote39(kick(20,20)).inner.payload},now);
        if(mutation==8) changed=f.rooms.receive(1,10,{6,words({1})},now);
        results(changed,words({10,0,0,3}),mutation==1?2U:3U);
        check(count(f.rooms.poll_votes(now+Vote::duration),26)==0,"cancelled map not applied on timeout");
        rejects([&]{f.reply(mutation==7?3U:2U,10,23,0);},"richonline_vote_not_active");
        if(mutation==1) {
            f.enter(30,30);f.rooms.receive(30,30,{4,words({1,2,1})},now);
            rejects([&]{f.rooms.receive(30,30,{40,words({10,23,0})},now);},"richonline_vote_not_active");
        }
    }
    Fixture f;f.rooms.receive(1,10,map_vote(),now);
    rejects([&]{f.rooms.set_game_pending(1,true);},"richonline_room_vote_active");
    rejects([&]{f.rooms.receive(2,20,{5,{1}},now);},"richonline_room_prepare_payload_invalid");
    rejects([&]{f.rooms.receive(4,40,{4,words({1,9,1})},now);},"richonline_room_join_team_invalid");
    rejects([&]{f.rooms.select_character(2,8,[]{throw CodecError("persist_failed");});},"persist_failed");
    f.reply(2,10,23,0);check(count(f.reply(3,10,23,0),26)==4,"failed changes preserve active vote");
    Fixture invalid;
    auto bad=map_vote();bad.payload[20]='X';
    rejects([&]{invalid.rooms.receive(1,10,bad,now);},"richonline_room_metadata_update_unproven");
    bad=map_vote();std::fill(bad.payload.begin()+148,bad.payload.begin()+180,0x41);
    rejects([&]{invalid.rooms.receive(1,10,bad,now);},"richonline_vote_map_extension_invalid");
    invalid.rooms.receive(1,10,{5,{}},now);
    rejects([&]{invalid.rooms.receive(2,20,map_vote(),now);},"richonline_vote_while_ready");
    Fixture timed;
    timed.rooms.receive(1,10,kick(),now);
    check(timed.rooms.poll_votes(now+Vote::duration-std::chrono::milliseconds(1)).empty(),"directory early timeout");
    const auto expired=timed.rooms.poll_votes(now+Vote::duration);
    results(expired,words({10,1,0,2}),3);check(count(expired,27)==4 && !timed.rooms.room_key(2),"idle timeout applies kick");
    check(timed.rooms.poll_votes(now+Vote::duration).empty(),"timeout not repeated");
    Fixture removed;
    removed.rooms.receive(1,10,kick(),now);
    removed.rooms.disconnect(1);removed.rooms.disconnect(2);removed.rooms.disconnect(3);
    check(removed.rooms.room_count()==0 && removed.rooms.poll_votes(now+Vote::duration).empty(),"empty room discards pending vote");
}
}
int main() {
    try { codec_contracts();state_machine();directory_map_and_kick();directory_lifecycle();
        std::cout<<"PASS lobby vote codecs, deadline, electorate and room action lifecycle\n";return 0;
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n';return 1; }
}
