#pragma once
#include "original_runtime_test_io.hpp"
#include "storage.hpp"

namespace original_runtime_test {
inline Bytes room_description(bool second_map) {
    Bytes description(208,0x6d);
    const auto put = [&](std::size_t offset,std::uint32_t value) {
        for (std::size_t i=0;i<4;++i) description.at(offset+i) = static_cast<std::uint8_t>(value>>(8*i));
    };
    const std::string title = "Original runtime room";
    std::copy(title.begin(),title.end(),description.begin()); description.at(title.size()) = 0;
    put(32,0x40); put(40,1); put(44,4); put(120,80);
    const std::string map = second_map ? "BS_1_2.emp" : "BS_1_1.emp";
    std::copy(map.begin(),map.end(),description.begin()+128); description.at(128+map.size()) = 0;
    const Bytes first{0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    const Bytes second{0xf2,0x6c,0x70,0x77,0x45,0x80,0xc7,0xfe,0x30,0xa6,0xcb,0x16,0xb1,0xaf,0xad,0x60};
    const auto& signature = second_map ? second : first;
    std::copy(signature.begin(),signature.end(),description.begin()+160);
    return description;
}
template<class Login>
void shared_room_runtime(Socket& owner,std::uint16_t port,Storage& storage,Login login) {
    const auto account = storage.dispatch("accounts.create",{{"username","RoomObserver"},
        {"password","\xe5\xaf\x86\xe7\xa0\x81"}}).at("account");
    owner.send({3,room_description(false)});
    const auto created = owner.receive();
    check(created.wire_type == 10 && created.payload.size() == 216,"runtime_room_creation_failed");
    const auto game = read_le(View(created.payload).first(4));
    const auto owner_id = read_le(View(created.payload).subspan(4,4));
    check(read_le(View(created.payload).subspan(68,4)) == owner_id,"runtime_room_owner_wrong");
    Socket observer(port);
    login(observer,account);
    const auto profile = observer.receive(), snapshot = observer.receive();
    check(profile.wire_type == 7 && profile.payload.size() == 268 &&
        read_le(View(profile.payload).first(4)) == owner_id &&
        read_le(View(profile.payload).subspan(12,4)) == game,"runtime_observer_owner_profile_missing");
    auto expected_snapshot = created.payload;
    std::fill(expected_snapshot.begin()+4,expected_snapshot.begin()+8,0);
    check(snapshot.wire_type == 5 && snapshot.payload == expected_snapshot,"runtime_room_state_isolated_between_sessions");
    Bytes unready; append_le(unready,1,4); append_le(unready,owner_id,4);
    const auto ready_list = observer.receive(), unready_list = observer.receive();
    check(ready_list.wire_type == 40 && ready_list.payload == Bytes(4,0) &&
        unready_list.wire_type == 41 && unready_list.payload == unready,"runtime_room_snapshot_members_wrong");
    Bytes configured; append_le(configured,game,4);
    const auto second = room_description(true);
    configured.insert(configured.end(),second.begin(),second.end());
    owner.send({23,configured});
    const auto changed = owner.receive(), observed = observer.receive();
    check(changed.wire_type == 26 && observed.wire_type == 26 && changed.payload == observed.payload &&
        changed.payload.size() == 212,"runtime_map_change_not_broadcast");
    check(read_le(View(changed.payload).first(4)) == game &&
        std::equal(second.begin()+128,second.end(),changed.payload.begin()+132),"runtime_map_change_resource_wrong");
    owner.send({5,{}});
    Bytes cancelled; append_le(cancelled,owner_id,4); append_le(cancelled,game,4);
    const auto own_ready = owner.receive(), other_ready = observer.receive();
    check(own_ready.wire_type == 13 && own_ready.payload == cancelled &&
        other_ready.wire_type == 13 && other_ready.payload == cancelled,"runtime_ready_confirmation_missing_before_cancellation");
    const auto own_cancelled = owner.receive(), other_cancelled = observer.receive();
    check(own_cancelled.wire_type == 96 && own_cancelled.payload == cancelled &&
        other_cancelled.wire_type == 96 && other_cancelled.payload == cancelled,"runtime_unimplemented_game_start_not_cancelled");
    owner.send({6,Bytes(4,0)});
    Bytes departed; append_le(departed,owner_id,4); append_le(departed,game,4); append_le(departed,0xffffffffU,4);
    const auto own_left = owner.receive(), other_left = observer.receive();
    check(own_left.wire_type == 14 && own_left.payload == departed &&
        other_left.wire_type == 14 && other_left.payload == departed,"runtime_room_leave_not_broadcast");
}
}
