#include "richonline_game_registry.hpp"
#include <array>
#include <iostream>

namespace {
using namespace richnet;
void check(bool condition,const char* code) { if (!condition) throw CodecError(code); }
RichonlineRoomSnapshot room(std::uint32_t channel) {
    RichonlineRoomSnapshot result{1,11,{},{{channel+1U,11,0,true}},channel};
    result.description.extension=Bytes(88,0xa5); return result;
}
RichonlineGameRedirect redirect() { return {{127,0,0,1},18602,123,{1,2,3,4,5,6,7,8}}; }
GameAdmission admission(std::uint32_t channel) { return richonline_expected_admission({channel,1,11},redirect()); }
RichonlineGameProvider provider(std::array<int,3>& cleaned) {
    return [&cleaned](const RichonlineRoomSnapshot& room) {
        return std::vector<RichonlineGamePlan>{{room.participants.front().connection,room.owner,redirect(),
            [] { return std::vector<Frame>{{1,{}}}; },
            [](const Envelope299&,View) { return std::vector<Frame>{{299,{1,2}}}; },
            [&cleaned,channel=room.channel] { ++cleaned.at(channel); }}};
    };
}
void identical_descriptors_except_channel_remain_independent() {
    std::array<int,3> cleaned{};
    RichonlineGameRegistry registry(provider(cleaned),0,std::chrono::seconds(30));
    for (std::uint32_t channel=0;channel<3;++channel) registry.prepare(room(channel));
    auto callbacks0=registry.callbacks(), callbacks1=registry.callbacks(), callbacks2=registry.callbacks();
    auto wrong=admission(2); wrong.id0=3;
    check(!callbacks2.authorize_admission(wrong),"unprepared_channel_accepted");
    check(callbacks0.authorize_admission(admission(0)),"channel0_admission_rejected");
    check(callbacks1.authorize_admission(admission(1)),"channel1_admission_rejected");
    check(callbacks2.authorize_admission(admission(2)),"channel2_admission_rejected");
    registry.cancel_room(1,1);
    check(registry.has_room(0,1) && !registry.has_room(1,1) && registry.has_room(2,1),"cancel_crossed_channel");
    check(cleaned==std::array<int,3>{0,1,0},"cancel_cleaned_other_channel");
    check(callbacks0.message(admission(0),{},{}).size()==1 && callbacks2.message(admission(2),{},{}).size()==1,
          "surviving_channel_game_cancelled");
    callbacks0.disconnected(admission(0));
    check(!registry.has_room(0,1) && registry.has_room(2,1),"disconnect_crossed_channel");
    registry.shutdown(); check(cleaned==std::array<int,3>{1,1,1},"cleanup_not_exactly_once_per_channel");
}
void expired_pending_room_does_not_cancel_other_channel_same_key() {
    std::array<int,3> cleaned{}; auto now=AdmissionClock::time_point{};
    RichonlineGameRegistry registry(provider(cleaned),0,std::chrono::seconds(30),[&] { return now; });
    registry.prepare(room(0)); now+=std::chrono::seconds(20); registry.prepare(room(1));
    now+=std::chrono::seconds(11);
    check(!registry.has_room(0,1) && registry.has_room(1,1),"expired_channel_cancelled_newer_other_channel");
    auto callbacks=registry.callbacks();
    check(!callbacks.authorize_admission(admission(0)) && callbacks.authorize_admission(admission(1)),"expiry_admission_scope_wrong");
    callbacks.disconnected(admission(1)); check(cleaned==std::array<int,3>{1,1,0},"expiry_cleanup_scope_wrong");
}
void admission_preserves_full_manager_dword() {
    const auto actual=encode_game_admission(richonline_expected_admission({0x11223344,1,11},redirect()),ClientVersion::richonline);
    check(actual.payload.size()==24 && View(actual.payload).first(4)[0]==0x44 && actual.payload[1]==0x33 &&
        actual.payload[2]==0x22 && actual.payload[3]==0x11,"manager_dword_truncated");
}
}
int main() {
    try {
        identical_descriptors_except_channel_remain_independent();
        expired_pending_room_does_not_cancel_other_channel_same_key();
        admission_preserves_full_manager_dword();
        std::cout<<"PASS channel-scoped game admission, cancellation, expiry and cleanup\n";
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
