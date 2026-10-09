#pragma once
#include "original_rooms.hpp"
#include "original_game_host.hpp"
#include <algorithm>

namespace room_handoff_test {
using namespace richnet;
inline void check(bool value, std::string_view reason) { if (!value) throw std::runtime_error(std::string(reason)); }
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code,std::string("wrong rejection: ")+error.what()); return; }
    throw std::runtime_error("expected rejection absent: "+std::string(code));
}
inline Bytes words(std::initializer_list<std::uint32_t> values) { Bytes result; for (const auto value : values) append_le(result,value,4); return result; }
inline void put(Bytes& data,std::size_t offset,std::uint32_t value) {
    for (std::size_t i=0;i<4;++i) data.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
inline std::uint32_t word(const Bytes& bytes,std::size_t offset) { return read_le(View(bytes).subspan(offset,4)); }
inline Bytes description(std::uint32_t minimum=1) {
    Bytes data(208,0xab); data[0]='B'; data[1]=0; put(data,32,0x40); put(data,40,minimum); put(data,44,2); put(data,120,80);
    constexpr std::string_view name="BS_1_1"; std::copy(name.begin(),name.end(),data.begin()+128); data[134]=0;
    constexpr std::array<std::uint8_t,16> signature{0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    std::copy(signature.begin(),signature.end(),data.begin()+160); put(data,176,3); return data;
}
inline Bytes profile(std::uint32_t user) {
    Bytes result(268,0xcd); put(result,0,user); put(result,12,0xffffffffU); put(result,40,user==12?2:4); return result;
}
inline std::shared_ptr<const OriginalMapCatalog> maps() {
    constexpr std::u8string_view source = RICHONLINE_LEGACY_RESOURCE_ROOT;
    const auto root=std::filesystem::path(std::u8string(source.begin(),source.end()));
    return std::make_shared<OriginalMapCatalog>(OriginalMapCatalog::load(root/"protocol-analysis"/"board-startup"/"maps"/"index.json"));
}
struct Fixture {
    AdmissionClock::time_point now=AdmissionClock::time_point{}+std::chrono::seconds(1);
    std::vector<OriginalRoomSnapshot> snapshots;
    unsigned closed=0;
    bool fail=false;
    std::shared_ptr<OriginalGameHost> host;
    OriginalRoomDirectory rooms;
    Fixture() : host(std::make_shared<OriginalGameHost>([this](const auto& room) { return provide(room); },
        OriginalGameEndpoint{{127,0,0,1},19022},std::chrono::milliseconds(100),[this] { return now; })),rooms(maps(),1,{},host,2) {
        for (const auto user : {12U,25U,39U}) rooms.enter(user,[user] { return profile(user); });
    }
    OriginalGamePlan plan(std::uint32_t user) {
        OriginalGamePlan result;
        result.startup={{0x1234,17.5,{2024,2,29,4},static_cast<std::uint8_t>(user==12?0:1),
            {{12,5,2,{1,2,3,4,5,6,7,8,9,10},0xa1},{25,9,3,{10,9,8,7,6,5,4,3,2,1},0xa2}},0x88,{0xfa,0x91}},
            {0x1234,0x89ab3456,7,{{123,456,789},{234,567,890}},{0xe1,0x92}},{19,-3,{0x11,0x22,0x80,0xff}}};
        result.map_ready=[] { return std::vector<Bytes>{}; };
        result.action=[](View) { return std::vector<Bytes>{}; };
        result.disconnected=[this] { ++closed; }; return result;
    }
    std::vector<OriginalGamePlanForUser> provide(const OriginalRoomSnapshot& room) {
        snapshots.push_back(room);
        if (fail) throw CodecError("test_provider_failure");
        std::vector<OriginalGamePlanForUser> result;
        for (const auto& player : room.players) result.push_back({player.user_id,plan(player.user_id)});
        return result;
    }
    void clear() { for (const auto user : {12U,25U,39U}) static_cast<void>(rooms.drain(user)); }
    void create(bool join=true,std::uint32_t minimum=1) {
        rooms.request(12,{3,description(minimum)});
        if (join) rooms.request(25,{4,words({0,3,1})});
        clear();
    }
    std::array<Frame,2> start() {
        rooms.request(12,{5,{}}); rooms.request(25,{5,{}});
        std::array<Frame,2> redirect;
        for (std::size_t i=0;i<3;++i) {
            const auto user=std::array{12U,25U,39U}[i]; const auto frames=rooms.drain(user);
            check(frames.size()==(i==2?3U:4U),"handoff frame count");
            check(frames[0].wire_type==13 && frames[0].payload==words({12,0}) && frames[1].wire_type==13 && frames[1].payload==words({25,0}),"ready transition order");
            check(frames[2].wire_type==26 && word(frames[2].payload,0)==0 && (word(frames[2].payload,36)&0x800U)!=0,"playing config absent");
            if (i<2) { check(frames[3].wire_type==22,"member redirect absent"); redirect[i]=frames[3]; }
        }
        return redirect;
    }
};
inline GameAdmission echo(const Frame& frame,std::uint32_t user) {
    check(frame.wire_type==22 && frame.payload.size()==18,"redirect packed length");
    OriginalGameRedirect redirect{{{127,0,0,1},19022},word(frame.payload,6),word(frame.payload,10),word(frame.payload,14)};
    return original_expected_admission({2,0,user},redirect);
}
inline Bytes admission_packet(const GameAdmission& admission) {
    return encode_frame(encode_game_admission(admission,ClientVersion::legacy),{Channel::game_c2s,{},ClientVersion::legacy});
}
inline void recovered(Fixture& fixture) {
    for (const auto user : {12U,25U,39U}) {
        const auto frames=fixture.rooms.drain(user); check(frames.size()==3,"recovery frame count");
        check(frames[0].wire_type==26 && (word(frames[0].payload,36)&0x800U)==0,"recovery must clear playing flag");
        check(frames[1].wire_type==96 && frames[1].payload==words({12,0}) && frames[2].wire_type==96 && frames[2].payload==words({25,0}),"recovery readiness wrong");
    }
    check(word(fixture.rooms.profile(12),12)==0 && word(fixture.rooms.profile(25),12)==0,"pending recovery must preserve room");
}
inline void removed(Fixture& fixture,std::initializer_list<std::uint32_t> recipients={12,25,39}) {
    for (const auto user : recipients) {
        const auto frames=fixture.rooms.drain(user); check(frames.size()==2,"active removal frame count");
        check(frames[0].wire_type==14 && frames[0].payload==words({12,0,25}) && frames[1].wire_type==14 && frames[1].payload==words({25,0,0xffffffffU}),"active removal order");
    }
}
}
