#include "richonline_game_registry.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* code){if(!value)throw CodecError(code);}
void callback_lifecycle(bool fail_refresh) {
    bool finished=false;int refreshed=0,confirmed=0,cleaned=0;
    RichonlineGameRegistry* instance=nullptr;
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& snapshot) {
        const auto& peer=snapshot.participants.at(0);
        RichonlineGamePlan value{peer.connection,peer.actor,{{127,0,0,1},18602,0x11223344,{1,2,3,4,5,6,7,8}},
            []{return std::vector<Frame>{};},[](const Envelope299&,View){return std::vector<Frame>{};},[&]{++cleaned;}};
        value.game_finished=[&]{return finished;};
        value.lobby_sent=[&](const Frame& frame) {
            if(frame.wire_type==58 && frame.payload==Bytes{1,2}){finished=false;++confirmed;}
        };
        value.profile_refresh_ready=[&] {
            ++refreshed;
            check(confirmed==1 && !finished && !instance->has_room(9,3),"refresh_before_retirement_or_durable_confirmation");
            if(fail_refresh)throw CodecError("injected_refresh_send_failure");
        };
        return std::vector<RichonlineGamePlan>{std::move(value)};
    },9,std::chrono::seconds(30));
    instance=&registry;
    RichonlineRoomSnapshot snapshot{3,11,{},{{1,11,0,true}},9};snapshot.description.extension=Bytes(88,0xa5);
    registry.prepare(snapshot);
    check(!registry.notify_lobby_sent(1,{58,{1,2}}) && refreshed==0,"premature_refresh");
    finished=true;
    check(!registry.notify_lobby_sent(2,{58,{1,2}}) && !registry.notify_lobby_sent(1,{57,{1,2}}) &&
        !registry.notify_lobby_sent(1,{58,{1}}) && refreshed==0 && confirmed==0,"unrelated_or_partial_refresh");
    bool threw=false;
    try{check(registry.notify_lobby_sent(1,{58,{1,2}}),"exact58_not_confirmed");}
    catch(const CodecError& error){check(std::string(error.what())=="injected_refresh_send_failure","wrong_failure");threw=true;}
    check(threw==fail_refresh && confirmed==1 && refreshed==1 && cleaned==1,"callback_counts_or_failure_hidden");
    check(!registry.has_room(9,3) && !registry.notify_lobby_sent(1,{58,{1,2}}),"failed_refresh_prevented_retirement");
    check(refreshed==1 && confirmed==1,"duplicate58_repeated_refresh");
    registry.shutdown();check(cleaned==1,"cleanup_repeated");
}
}
int main() {
    try{callback_lifecycle(false);callback_lifecycle(true);std::cout<<"profile refresh registry tests PASS\n";}
    catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
