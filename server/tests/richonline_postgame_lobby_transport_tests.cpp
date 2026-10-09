#include "server_lobby_adapter.hpp"
#include <sqlite3.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if(!value) throw std::runtime_error(reason); }
BootstrapBlobs blobs(bool rooms=true) {
    BootstrapBlobs result{};
    result.provenance="Isolated postgame transport fixture with explicit opaque values";
    result.game_capacity=8;result.player_capacity=100;
    if(rooms) result.room_unknown_prefix=0x12345678;
    result.setting_text="14";result.stage_progress={1,1,2,0};
    const auto bits=std::bit_cast<std::uint64_t>(2.5);
    for(std::size_t i=0;i<8;++i) result.unknown_completion[20+i]=static_cast<std::uint8_t>(bits>>(8*i));
    return result;
}
void sql(const std::filesystem::path& path,const char* command) {
    sqlite3* db=nullptr;const auto name=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture SQL open");
    const auto result=sqlite3_exec(db,command,nullptr,nullptr,nullptr);
    sqlite3_close(db);check(result==SQLITE_OK,"fixture SQL failed");
}
std::uint32_t create(Storage& storage,const char* name) {
    return storage.dispatch("accounts.create",{{"username",name},{"password","p"}})
        .at("account").at("role_id").get<std::uint32_t>();
}
std::vector<Frame> decode(const std::vector<Bytes>& packets) {
    std::vector<Frame> result;
    for(const auto& packet:packets) result.push_back(decode_frame(packet,{Channel::lobby_s2c,219,ClientVersion::richonline}));
    return result;
}
std::vector<Bytes> feed(RichLobbySession& session,const Frame& frame) {
    return session.feed(encode_frame(frame,{Channel::lobby_c2s,219,ClientVersion::richonline}));
}
bool has(const std::vector<Frame>& frames,std::uint32_t type) {
    return std::any_of(frames.begin(),frames.end(),[type](const Frame& frame){return frame.wire_type==type;});
}
Frame scalar(std::uint32_t type,std::uint32_t value) {
    Bytes bytes;append_le(bytes,value,4);return {type,std::move(bytes)};
}
std::vector<Bytes> enter(RichLobbySession& session,const char* name,std::uint32_t actor) {
    static_cast<void>(session.start());
    static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},
        {Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
    Bytes login(144);const auto length=std::char_traits<char>::length(name);
    std::copy(name,name+length,login.begin()+12);login[76]='p';
    static_cast<void>(feed(session,{58,login}));
    static_cast<void>(feed(session,scalar(34,actor)));
    return feed(session,scalar(7,0));
}
Frame room_create() {
    Bytes bytes(128);bytes[0]='r';bytes[4]=0;bytes[76]='s';bytes[77]=0;
    bytes[32]=0x40;bytes[36]=2;bytes[40]=1;bytes[72]=1;bytes[120]=88;bytes[124]=1;
    bytes.insert(bytes.end(),88,0xa5);return {3,std::move(bytes)};
}
GameSettlementRequest settlement() {
    std::array<std::uint32_t,21> levels{};
    for(std::size_t i=0;i<levels.size();++i) levels[i]=static_cast<std::uint32_t>(i)*100;
    return {"transport:settlement","transport:match","stage",GameOutcome::win,0,std::nullopt,
        {"Explicit isolated transport test policy",{10,20,3},{5,8,1},{2,0,0},{3,4,0},levels,0},
        GameSettlementDelivery{1,1,0,0,7,true,{}}};
}
void terminal_and_reconnect(const std::filesystem::path& path) {
    Storage storage(path);const auto actor=create(storage,"PostgameOwner");
    bool finish=false;const auto result=settlement();
    auto registry=std::make_shared<RichonlineGameRegistry>([&](const RichonlineRoomSnapshot& room) {
        RichonlineGamePlan plan{room.participants.front().connection,room.owner,
            {{127,0,0,1},18602,123,{1,2,3,4,5,6,7,8}},
            [] {return std::vector<Frame>{};},
            [](const Envelope299&,View) {return std::vector<Frame>{};},[] {}};
        plan.game_finished=[&] {return finish;};
        plan.terminal_pending=[&] {return finish;};
        plan.lobby_sent=[&](const Frame& frame) {
            check(frame.wire_type==58,"wrong terminal callback");
            storage.advance_game_settlement_outbox("PostgameOwner",actor,result.operation_id,2);
            finish=false;
        };
        return std::vector<RichonlineGamePlan>{std::move(plan)};
    },0,std::chrono::seconds(30));
    ServerLobbyAdapter adapter(storage,blobs());adapter.set_game_registry(registry);
    const auto options=ServerLobbyOptions{"127.0.0.1",0}.transport();
    RichLobbySession owner(options,adapter.callbacks());
    check(has(decode(enter(owner,"PostgameOwner",actor)),7),"channel bootstrap absent");
    check(has(decode(feed(owner,room_create())),10),"room not created");
    check(has(decode(feed(owner,{5,{}})),22),"game not admitted");
    static_cast<void>(storage.settle_game("PostgameOwner",actor,result));
    storage.advance_game_settlement_outbox("PostgameOwner",actor,result.operation_id,0);
    storage.advance_game_settlement_outbox("PostgameOwner",actor,result.operation_id,1);
    finish=true;
    const auto terminal=owner.poll();const auto terminal_frames=decode(terminal);
    check(terminal_frames.size()==2&&terminal_frames[0].wire_type==96&&
        terminal_frames[1].wire_type==58,"wrong terminal frames");
    check(storage.pending_game_settlement_profile_refreshes("PostgameOwner",actor).empty(),
        "profile intent visible before terminal send");
    owner.sent(terminal[0]);
    check(owner.poll().empty(),"profile queued before exact terminal58");
    owner.sent(terminal[1]);
    const auto refresh=owner.poll();const auto frames=decode(refresh);
    check(frames.size()==1&&frames[0].wire_type==19&&frames[0].payload.size()==144,
        "postgame profile19 not queued");
    check(storage.pending_game_settlement_profile_refreshes("PostgameOwner",actor).size()==1,
        "queued profile prematurely confirmed");
    check(decode(feed(owner,{5,{}})).empty(),"new game ready before owner profile delivery");
    const auto spectator=create(storage,"PostgameObserver");
    RichLobbySession observer(options,adapter.callbacks());
    const auto bootstrap=decode(enter(observer,"PostgameObserver",spectator));
    const auto latest=std::find_if(bootstrap.begin(),bootstrap.end(),[actor](const Frame& frame) {
        return frame.wire_type==7&&frame.payload.size()==272&&read_le(View(frame.payload).first(4))==actor;
    });
    check(latest!=bootstrap.end(),"late observer missing actor cache");
    check(std::equal(frames[0].payload.begin()+24,frames[0].payload.begin()+36,
        latest->payload.begin()+24)&&latest->payload[144]==0,
        "late observer received stale profile or lost equipment");
    owner.finish();observer.finish();
    check(storage.pending_game_settlement_profile_refreshes("PostgameOwner",actor).size()==1,
        "unsent profile lost on disconnect");
    ServerLobbyAdapter restarted(storage,blobs());RichLobbySession recovered(options,restarted.callbacks());
    const auto reconnect=enter(recovered,"PostgameOwner",actor);const auto recovered_frames=decode(reconnect);
    const auto update=std::find_if(recovered_frames.begin(),recovered_frames.end(),[](const Frame& frame) {
        return frame.wire_type==19;
    });
    check(update!=recovered_frames.end()&&update->payload.size()==144,"reconnect did not restage profile");
    check(decode(feed(recovered,room_create())).size()>0,"reconnect room creation failed");
    check(decode(feed(recovered,{5,{}})).empty(),"reconnect ready before profile whole-send");
    recovered.sent(encode_frame(*update,{Channel::lobby_s2c,219,ClientVersion::richonline}));
    check(storage.pending_game_settlement_profile_refreshes("PostgameOwner",actor).empty(),
        "whole-send failed to confirm durable refresh");
    recovered.finish();
}
void deferred_stage_preserves_lobby(const std::filesystem::path& path) {
    Storage storage(path);const auto actor=create(storage,"DeferredOwner");
    auto result=settlement();result.operation_id="deferred:settlement";result.match_id="deferred:match";
    static_cast<void>(storage.settle_game("DeferredOwner",actor,result));
    for(std::uint32_t index=0;index<3;++index)
        storage.advance_game_settlement_outbox("DeferredOwner",actor,result.operation_id,index);
    sql(path,"CREATE TRIGGER block_profile_stage BEFORE UPDATE ON game_settlement_profile_refreshes "
        "BEGIN SELECT RAISE(ABORT,'fixture stage failure'); END");
    std::string logs;ServerLobbyAdapter adapter(storage,blobs(),[&](const std::string& event,const nlohmann::json& data) {
        logs+=event+data.dump();
    });
    RichLobbySession session(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());
    const auto bootstrap=decode(enter(session,"DeferredOwner",actor));
    check(has(bootstrap,7)&&!has(bootstrap,19)&&session.state()==LobbyState::authenticated,
        "stage failure broke channel bootstrap");
    check(storage.pending_game_settlement_profile_refreshes("DeferredOwner",actor).size()==1&&
        logs.find("richonline_postgame_profile_deferred")!=std::string::npos,
        "stage failure lost pending intent or diagnostics");
    sql(path,"DROP TRIGGER block_profile_stage");
    check(has(decode(feed(session,room_create())),10),"room create failed after deferred stage");
    const auto ready=feed(session,{5,{}});const auto ready_frames=decode(ready);
    check(has(ready_frames,19)&&!has(ready_frames,13)&&session.state()==LobbyState::authenticated,
        "ready was not deferred until profile refresh sent");
    const auto profile=std::find_if(ready_frames.begin(),ready_frames.end(),[](const Frame& frame) {
        return frame.wire_type==19;
    });
    session.sent(encode_frame(*profile,{Channel::lobby_s2c,219,ClientVersion::richonline}));
    check(storage.pending_game_settlement_profile_refreshes("DeferredOwner",actor).empty()&&
        has(decode(feed(session,{5,{}})),13),"deferred intent did not recover");
    session.finish();
}
void no_directory_without_intent(const std::filesystem::path& path) {
    Storage storage(path);const auto actor=create(storage,"PlainOwner");
    ServerLobbyAdapter adapter(storage,blobs(false));
    RichLobbySession session(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());
    check(has(decode(enter(session,"PlainOwner",actor)),7)&&session.state()==LobbyState::authenticated,
        "ordinary channel bootstrap wrongly requires room directory");
    session.finish();
}
}
int main() {try {
    const auto root=std::filesystem::temp_directory_path()/
        ("postgame-lobby-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    terminal_and_reconnect(root/"accounts.sqlite3");
    deferred_stage_preserves_lobby(root/"deferred.sqlite3");
    no_directory_without_intent(root/"plain.sqlite3");
    std::filesystem::remove_all(root);
    std::cout<<"postgame lobby transport tests PASS\n";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
