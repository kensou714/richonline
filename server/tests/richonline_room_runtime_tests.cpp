#include "lobby_runtime.hpp"
#include "codec.hpp"
#include "richonline_game_startup.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void check(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
struct Network {
    Network() { WSADATA data{}; check(WSAStartup(MAKEWORD(2,2), &data) == 0, "winsock_start_failed"); }
    ~Network() { WSACleanup(); }
};
struct Peer {
    SOCKET socket = INVALID_SOCKET;
    std::int32_t key = 0;
    explicit Peer(std::uint16_t port) {
        socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        check(socket != INVALID_SOCKET, "socket_failed");
        try {
            const DWORD timeout = 3000;
            for (const auto option : {SO_RCVTIMEO, SO_SNDTIMEO})
                check(setsockopt(socket,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) == 0,"socket_timeout_failed");
            sockaddr_in target{};
            target.sin_family = AF_INET; target.sin_port = htons(port);
            check(inet_pton(AF_INET,"127.0.0.1",&target.sin_addr) == 1,"invalid_address");
            check(::connect(socket,reinterpret_cast<sockaddr*>(&target),sizeof(target)) == 0,"connect_failed");
        } catch (...) { close(); throw; }
    }
    Peer(std::uint16_t port, std::int32_t exponent, const std::string& name) : Peer(port) {
        key=modpow_signed32(64,exponent,251);
        try {
            read(20);
            Bytes public_key;
            append_le(public_key,static_cast<std::uint32_t>(modpow_signed32(5,exponent,251)),4);
            raw(encode_frame({759,public_key},{Channel::lobby_c2s,{},ClientVersion::richonline}));
            Bytes login(144,0);
            std::copy(name.begin(),name.end(),login.begin()+12);
            login[76] = 'p';
            send({58,login});
            check(receive().wire_type == 67,"role_list_missing");
            const auto result=receive();
            check(result.wire_type==1 && result.payload.size()>=8,"login_result_missing");
            const auto channels=read_le(View(result.payload).subspan(4,4));
            check(channels>0 && channels<=3,"fixture_channel_count_invalid");
            for (std::uint32_t index=0;index<channels;++index) {
                const auto channel=receive();
                check(channel.wire_type==3 && channel.payload.size()==80 &&
                    read_le(View(channel.payload).subspan(32,4))==index,"channel_catalog_missing");
            }
        } catch (...) { close(); throw; }
    }
    ~Peer() { close(); }
    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    void close() { if (socket != INVALID_SOCKET) { closesocket(socket); socket = INVALID_SOCKET; } }
    void raw(View data) {
        while (!data.empty()) {
            const int count = ::send(socket,reinterpret_cast<const char*>(data.data()),static_cast<int>(data.size()),0);
            check(count > 0,"send_failed"); data = data.subspan(static_cast<std::size_t>(count));
        }
    }
    void send(const Frame& frame) { raw(encode_frame(frame,{Channel::lobby_c2s,key,ClientVersion::richonline})); }
    Bytes read(std::size_t size) {
        Bytes bytes(size);
        for (std::size_t offset=0;offset<size;) {
            const auto count = recv(socket,reinterpret_cast<char*>(bytes.data()+offset),static_cast<int>(size-offset),0);
            check(count > 0,"receive_failed"); offset += static_cast<std::size_t>(count);
        }
        return bytes;
    }
    Frame receive() {
        auto bytes = read(8);
        const auto total = read_le(View(bytes).subspan(4,4));
        check(total >= 8 && total <= max_frame_total,"bad_frame_total");
        auto payload = read(total-8); bytes.insert(bytes.end(),payload.begin(),payload.end());
        return decode_frame(bytes,{Channel::lobby_s2c,key,ClientVersion::richonline});
    }
    Frame game_receive() {
        auto bytes=read(8);
        const auto total=read_le(View(bytes).subspan(4,4));
        check(total>=8 && total<=max_frame_total,"bad_game_frame_total");
        auto payload=read(total-8); bytes.insert(bytes.end(),payload.begin(),payload.end());
        return decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
    }
    void game_send(const Frame& frame) { raw(encode_frame(frame,{Channel::game_c2s,{},ClientVersion::richonline})); }
    Frame until(std::uint32_t type) {
        for (std::size_t i=0;i<32;++i) {
            auto frame = receive();
            if (frame.wire_type == type) return frame;
            check(frame.wire_type != 22,"unexpected_game_admission_without_game_runtime");
        }
        throw std::runtime_error("expected_event_missing");
    }
};
Bytes words(std::initializer_list<std::uint32_t> values) {
    Bytes bytes;
    for (const auto value : values) append_le(bytes,value,4);
    return bytes;
}
void put(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for (std::size_t i=0;i<4;++i) bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(i*8));
}
Json config() {
    Json value{{"provenance","Synthetic two-client room integration fixture; no actual map viability asserted."},
        {"game_capacity",8},{"player_capacity",100},{"stage_progress",{1,1,2,0}},{"setting_text","14"},
        {"room_unknown_prefix",0x12345678},
        {"network",{{"bind_host","127.0.0.1"},{"advertised_host","127.0.0.1"},
                    {"lobby_port",0},{"http_port",0},{"black_port",0}}}};
    for (const auto& [name,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"unknown_channel_record_hex",80},{"unknown_role_record_hex",208},{"unknown_profile_record_hex",272},
        {"unknown_login_result_hex",16},{"unknown_identity_record_hex",16},{"unknown_empty_list_hex",4},
        {"unknown_bank_config_hex",32}}) value[name]=std::string(size*2,'0');
    value["unknown_completion_hex"] = std::string(40,'0')+"000000000000f03f";
    return value;
}
Bytes room_request() {
    Bytes bytes(216,0);
    bytes[0]='R'; put(bytes,32,0xc0); put(bytes,40,2); put(bytes,44,4);
    put(bytes,48,0xffffffffU); put(bytes,60,0xffffffffU); put(bytes,64,0xffffffffU);
    put(bytes,68,2); put(bytes,72,2); put(bytes,120,88); put(bytes,124,1);
    const std::string name="BS_1_1";
    std::copy(name.begin(),name.end(),bytes.begin()+128);
    return bytes;
}
void verify_pair(const Frame& frame,std::uint32_t actor,std::uint32_t room) {
    check(frame.payload.size() >= 8,"event_pair_short");
    check(read_le(View(frame.payload).first(4)) == actor && read_le(View(frame.payload).subspan(4,4)) == room,
          "event_actor_room_wrong");
}
void runtime_game_flow(Storage& storage,const std::filesystem::path& bootstrap,std::uint32_t actor) {
    std::atomic_int ready{0},actions{0},cleaned{0};
    RichonlineRuntimeGame options{0,0,std::chrono::seconds(30),
        [&](std::uint16_t port,const RichonlineRoomSnapshot& room) {
            check(room.participants.size()==1,"unexpected_game_fixture_membership");
            const auto& member=room.participants.front();
            const RichonlineGameRedirect redirect{{127,0,0,1},port,0xabcdef12,{1,2,3,4,5,6,7,8}};
            const auto admission=richonline_expected_admission({0,room.key,member.actor},redirect);
            RichonlineStartupPlan startup{
                {0x1357,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                    {{static_cast<std::int16_t>(member.actor),1,2,{1,2,3,4,5,6,7,8,9,10},0xb1},
                     {-1,9,3,{11,12,13,14,15,16,17,18,19,20},0xb2}}},
                {0x1357,0x2468,100,{{2000,3000,4},{5000,6000,7}}},{9,-3},
                [&] { ++ready; return std::vector<Bytes>{{0x10,0x40,0x57,0x13,0,0,0}}; },
                [&](const Envelope299&,View) { ++actions; return std::vector<Bytes>{{4,0x40,0x57,0x13,
                    0x69,0x24,0,0,100,0,0,0,0xd0,7,0,0,0xb8,11,0,0,4,0,0,0,0x88,19,0,0,0x70,23,0,0,7,0,0,0}}; },
                [&] { ++cleaned; }};
            auto callbacks=make_richonline_game_callbacks(
                [startup](const GameAdmission&)->std::optional<RichonlineStartupPlan> { return startup; },
                [](std::size_t size) { return Bytes(size,0x81); });
            check(callbacks.authorize_admission(admission),"fixture_plan_not_authorized");
            return std::vector<RichonlineGamePlan>{{member.connection,member.actor,redirect,
                [callbacks,admission] { return callbacks.admitted(admission); },
                [callbacks,admission](const Envelope299& envelope,View plain) { return callbacks.message(admission,envelope,plain); },
                [callbacks,admission] { callbacks.disconnected(admission); }}};
        }};
    LobbyRuntime runtime(storage,bootstrap,[](const std::string&,const Json&){},std::move(options));
    check(runtime.status().at("gameListenerReady").get<bool>(),"game_listener_not_ready");
    Peer lobby(runtime.status().at("lobbyPort").get<std::uint16_t>(),17,"room-a");
    lobby.send({34,words({actor})}); lobby.until(70); lobby.send({7,words({0})}); lobby.until(30);
    lobby.send({3,room_request()}); const auto created=lobby.until(10);
    const auto room=read_le(View(created.payload).first(4));
    lobby.send({5,{}}); verify_pair(lobby.until(13),actor,room);
    const auto redirect=lobby.until(22);
    check(redirect.payload.size()==18,"runtime_redirect_length_invalid");
    const auto game_port=static_cast<std::uint16_t>(read_le(View(redirect.payload).subspan(4,2)));
    check(game_port==runtime.status().at("gamePort").get<std::uint16_t>(),"redirect_wrong_listener");
    GameAdmission admission{0,room,actor,{},read_le(View(redirect.payload).subspan(6,4)),{}};
    std::copy(redirect.payload.begin()+10,redirect.payload.end(),admission.opaque8.begin());
    Peer game(game_port);
    game.game_send(encode_game_admission(admission,ClientVersion::richonline));
    const auto admitted=game.game_receive();
    check(admitted.wire_type==1 && admitted.payload.empty(),"runtime_admission_ack_must_precede_init");
    auto plain=decode_inner(decode_envelope(game.game_receive(),ClientVersion::richonline).encoded);
    check(plain.size()==52 && read_le(View(plain).first(2))==0x4000,"runtime_init_missing");
    auto send=[&](Bytes data) { game.game_send(richonline_board_frame(data,{0,-1},Bytes(data.size()+2,0x81))); };
    send({1,0}); send({0,0});
    plain=decode_inner(decode_envelope(game.game_receive(),ClientVersion::richonline).encoded);
    check(plain.size()==36 && read_le(View(plain).first(2))==0x4004,"runtime_snapshot_missing");
    plain=decode_inner(decode_envelope(game.game_receive(),ClientVersion::richonline).encoded);
    check(plain==Bytes({0x10,0x40,0x57,0x13,0,0,0}),"runtime_opening_missing");
    send({0x10,0,0x69,0x24,6,0,0,0});
    plain=decode_inner(decode_envelope(game.game_receive(),ClientVersion::richonline).encoded);
    check(read_le(View(plain).first(2))==0x4004 && actions==1 && ready==1,"runtime_action_not_dispatched");
    game.close();
    verify_pair(lobby.until(96),actor,room);
    runtime.stop();
    check(cleaned==1 && !runtime.status().at("gameListenerReady").get<bool>(),"game_stop_or_cleanup_wrong");
}
void rejected_game_start_keeps_room_connected(const std::filesystem::path& root) {
    Storage storage(root/"start-rejection.sqlite3");
    const auto actor=storage.dispatch("accounts.create",{{"username","reject-start"},{"password","p"}})
        .at("account").at("role_id").get<std::uint32_t>();
    std::atomic_int attempts{0},reported{0};
    RichonlineRuntimeGame options{0,0,std::chrono::seconds{30},
        [&](std::uint16_t,const RichonlineRoomSnapshot&)->std::vector<RichonlineGamePlan> {
            ++attempts; throw CodecError("richonline_boss_category_unsupported");
        }};
    LobbyRuntime runtime(storage,root/"bootstrap.json",[&](const std::string& event,const Json& detail) {
        if (event=="richonline_game_start_rejected" && detail.at("reason")=="richonline_boss_category_unsupported") ++reported;
    },std::move(options));
    Peer peer(runtime.status().at("lobbyPort").get<std::uint16_t>(),17,"reject-start");
    peer.send({34,words({actor})}); peer.until(70); peer.send({7,words({0})}); peer.until(30);
    peer.send({3,room_request()}); const auto created=peer.until(10);
    const auto room=read_le(View(created.payload).first(4));
    for (unsigned attempt=0;attempt<2;++attempt) {
        peer.send({5,{}});
        verify_pair(peer.receive(),actor,room);
        const auto cancelled=peer.receive();
        check(cancelled.wire_type==96,"failed_start_did_not_cancel_ready"); verify_pair(cancelled,actor,room);
        peer.send({10,words({attempt+1})});
        check(peer.until(18).payload==words({actor,attempt+1}),"failed_start_closed_or_locked_room");
    }
    check(attempts==2 && reported==2,"start_failure_reason_not_observable");
    peer.close(); runtime.stop();
}
void start_login(Peer& peer,const std::string& username,const std::string& password) {
    peer.key=modpow_signed32(64,19,251);
    peer.read(20);
    Bytes public_key; append_le(public_key,static_cast<std::uint32_t>(modpow_signed32(5,19,251)),4);
    peer.raw(encode_frame({759,public_key},{Channel::lobby_c2s,{},ClientVersion::richonline}));
    Bytes payload(144,0);
    check(username.size()<64 && password.size()<64,"login_fixture_slot_overflow");
    std::copy(username.begin(),username.end(),payload.begin()+12);
    std::copy(password.begin(),password.end(),payload.begin()+76);
    peer.send({58,payload});
}
std::uint32_t enter_registered_role(Peer& peer) {
    const auto roles=peer.receive();
    check(roles.wire_type==67 && roles.payload.size()==212 && read_le(View(roles.payload).first(4))==1,
        "auto_registration_role_catalog_missing");
    const auto actor=read_le(View(roles.payload).subspan(4,4));
    const auto login=peer.receive();
    check(actor>0 && login.wire_type==1 && login.payload.size()==16 && read_le(View(login.payload).first(4))==actor,
        "auto_registration_login_role_wrong");
    check(peer.receive().wire_type==3,"auto_registration_channels_missing");
    peer.send({34,words({actor})}); peer.until(70); peer.send({7,words({0})}); peer.until(30);
    return actor;
}
void require_login_closed(Peer& peer) {
    const auto rejected=peer.receive();
    check(rejected.wire_type==0xffffffffU && rejected.payload==Bytes({58,0,0,0,0x9b,0xff,0xff,0xff,0}),
        "login_failure_response_missing_or_wrong");
    char byte{};
    const auto count=recv(peer.socket,&byte,1,0);
    check(count==0 || (count==SOCKET_ERROR && WSAGetLastError()==WSAECONNRESET),"rejected_login_not_closed");
}
void first_login_registers_and_reuses_persistent_credentials(const std::filesystem::path& root) {
    const auto database=root/"auto-register.sqlite3", bootstrap=root/"bootstrap.json";
    const std::string username="fresh-"+std::to_string(GetCurrentProcessId()), password="first-login-secret";
    Json saved;
    {
        Storage storage(database);
        check(storage.roles_for_username(username).empty(),"registration_fixture_not_empty");
        LobbyRuntime runtime(storage,bootstrap,[](const std::string&,const Json&){});
        Peer peer(runtime.status().at("lobbyPort").get<std::uint16_t>());
        start_login(peer,username,password);
        const auto actor=enter_registered_role(peer);
        const auto roles=storage.roles_for_username(username);
        check(roles.size()==1,"auto_registration_role_not_persisted"); saved=roles[0];
        check(saved.at("role_id")==actor && saved.at("username")==username && saved.at("name")==username &&
            saved.at("model")==0 && saved.at("level")==6 && saved.at("experience")==700 &&
            saved.at("coins")==10000.0 && saved.at("gold")==10000.0 && saved.at("bank")==0.0,
            "auto_registration_default_assets_wrong");
        peer.close(); runtime.stop();
    }
    {
        Storage storage(database);
        check(storage.roles_for_username(username)==Json::array({saved}),"registered_role_lost_after_reopen");
        LobbyRuntime runtime(storage,bootstrap,[](const std::string&,const Json&){});
        const auto port=runtime.status().at("lobbyPort").get<std::uint16_t>();
        Peer wrong(port); start_login(wrong,username,"wrong-secret"); require_login_closed(wrong);
        check(storage.roles_for_username(username)==Json::array({saved}),"wrong_password_overwrote_registered_role");
        Peer returning(port); start_login(returning,username,password);
        check(enter_registered_role(returning)==saved.at("role_id").get<std::uint32_t>(),"relogin_changed_role_identity");
        returning.close(); runtime.stop();
    }
    {
        Storage storage(database);
        const auto current=storage.dispatch("config.get",Json::object());
        auto settings=current.at("settings"); settings["registration_enabled"]=false;
        storage.dispatch("config.update",{{"expectedRevision",current.at("revision")},{"settings",settings}});
        LobbyRuntime runtime(storage,bootstrap,[](const std::string&,const Json&){});
        const auto port=runtime.status().at("lobbyPort").get<std::uint16_t>();
        Peer newcomer(port); start_login(newcomer,"disabled-new-user",password); require_login_closed(newcomer);
        check(storage.roles_for_username("disabled-new-user").empty(),"disabled_registration_created_role");
        Peer existing(port); start_login(existing,username,password);
        check(enter_registered_role(existing)==saved.at("role_id").get<std::uint32_t>(),"disabled_registration_rejected_existing_account");
        check(storage.roles_for_username(username)==Json::array({saved}),"relogin_reset_registered_assets");
        existing.close(); runtime.stop();
    }
}
void three_channel_tcp_isolation(const std::filesystem::path& root) {
    auto configured=config();
    configured["grant_test_rp_certificate"]=true;
    configured["channels"]=Json::array();
    for (std::uint32_t channel=0;channel<3;++channel)
        configured["channels"].push_back({{"key",channel},{"name_utf8","channel"+std::to_string(channel)},
            {"room_capacity",8},{"player_capacity",100},{"lobby_type",channel},{"status",1},
            {"min_gold",0},{"max_gold",1e9},{"min_level",0},{"max_level",999},{"wire_record_hex",std::string(160,'0')}});
    const auto bootstrap=root/"three-channel.json";
    { std::ofstream file(bootstrap); file<<configured; check(file.good(),"channel_fixture_write_failed"); }
    Storage storage(root/"channels.sqlite3");
    const auto create=[&](const char* user) { return storage.dispatch("accounts.create",{{"username",user},{"password","p"}})
        .at("account").at("role_id").get<std::uint32_t>(); };
    const auto id0=create("channel0"),id1=create("channel1"),id2=create("channel2"),watcher=create("watcher");
    LobbyRuntime runtime(storage,bootstrap,[](const std::string&,const Json&){});
    const auto port=runtime.status().at("lobbyPort").get<std::uint16_t>();
    const auto channel_document=[&] {
        Peer http(runtime.status().at("httpPort").get<std::uint16_t>());
        const std::string request="GET /gameinfo/RichNetLogin.txt HTTP/1.1\r\nHost: localhost\r\n\r\n";
        http.raw(View(reinterpret_cast<const std::uint8_t*>(request.data()),request.size()));
        std::string response;
        char buffer[2048];
        int count;
        while ((count=recv(http.socket,buffer,sizeof(buffer),0))>0)
            response.append(buffer,static_cast<std::size_t>(count));
        check(count==0,"channel_http_read_failed");
        return response;
    };
    check(channel_document().find("channelsum=3\n")!=std::string::npos,"runtime_http_catalog_not_wired");
    const auto enter=[&](Peer& peer,std::uint32_t actor,std::uint32_t channel,bool select_role=true) {
        if(select_role) { peer.send({34,words({actor})}); check(peer.until(70).payload==words({actor}),"selection_not_confirmed"); }
        peer.send({7,words({channel})});
        const auto identity=peer.receive();
        check(identity.wire_type==9 && read_le(View(identity.payload).subspan(4,4))==channel,"wrong_channel_identity");
        std::size_t rooms=0;
        bool equipped=false,owned=false;
        for (std::size_t index=0;index<32;++index) {
            const auto frame=peer.receive();
            if (frame.wire_type==5) ++rooms;
            if (frame.wire_type==7 && read_le(View(frame.payload).first(4))==actor)
                equipped=read_le(View(frame.payload).subspan(196,4))==13;
            if (frame.wire_type==2)
                owned=frame.payload.size()==12 && read_le(View(frame.payload).first(4))==1 &&
                    read_le(View(frame.payload).subspan(4,4))==13;
            if (frame.wire_type==30) {
                check(equipped && owned,"tcp_channel_rp_certificate_gate_not_satisfied");
                return rooms;
            }
        }
        throw std::runtime_error("channel_completion_missing");
    };
    Peer a(port,11,"channel0"); check(enter(a,id0,0)==0,"channel0_initial_rooms_wrong");
    Peer b(port,13,"channel1"); check(enter(b,id1,1)==0,"channel1_initial_rooms_wrong");
    a.send({3,room_request()}); const auto created_a=a.receive(); check(created_a.wire_type==10,"other_channel_profile_leaked");
    b.send({3,room_request()}); check(b.receive().wire_type==10,"other_channel_room_leaked");
    Peer c(port,17,"channel2"); check(enter(c,id2,2)==0,"other_channel_snapshot_leaked");
    Peer observer(port,19,"watcher"); check(enter(observer,watcher,1)==1,"same_channel_snapshot_missing");
    const auto document=channel_document();
    check(document.find("LobbyName=channel0\nMaxPlayerNum=100\nNowPlayerNum=1\n")!=std::string::npos &&
          document.find("LobbyName=channel1\nMaxPlayerNum=100\nNowPlayerNum=2\n")!=std::string::npos &&
          document.find("LobbyName=channel2\nMaxPlayerNum=100\nNowPlayerNum=1\n")!=std::string::npos,
          "runtime_http_channel_population_not_wired");
    check(b.receive().wire_type==7,"same_channel_observer_profile_missing");
    b.send({10,words({8})});
    check(b.receive().wire_type==18 && observer.receive().wire_type==18,"same_channel_character_update_missing");
    c.send({3,room_request()}); check(c.receive().wire_type==10,"other_channel_character_leaked");
    // Reproduce leaving a room and choosing a channel from the room list on
    // the same authenticated socket. The former live binary closed C2S8.
    a.send({6,words({1})});
    verify_pair(a.until(14),id0,read_le(View(created_a.payload).first(4)));
    check(a.receive().wire_type==57,"room_list_transition_missing_removal");
    a.send({8,words({0})});
    const auto left=a.receive();
    check(left.wire_type==16 && left.payload.empty(),"channel_switch_missing16_or_closed_socket");
    for(const auto destination:std::array<std::uint32_t,4>{2,0,2,0}) {
        check(enter(a,id0,destination,false)==(destination==2?1U:0U),"channel_switch_stale_room_snapshot");
        if(destination==2) check(c.receive().wire_type==7,"channel_switch_new_presence_missing");
        a.send({8,words({0})});
        const auto acknowledgement=a.receive();
        check(acknowledgement.wire_type==16 && acknowledgement.payload.empty(),"repeated_channel_switch_closed_socket");
        if(destination==2) check(c.receive().wire_type==55,"channel_switch_old_presence_retained");
    }
    check(enter(a,id0,0,false)==0,"channel_switch_cannot_return_without_relogin");
    a.close(); b.close(); c.close(); observer.close(); runtime.stop();
}
}
int main() {
    try {
        Network network;
        const auto root=std::filesystem::absolute("richonline-room-runtime-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        Storage storage(root/"accounts.sqlite3");
        const auto first=storage.dispatch("accounts.create",{{"username","room-a"},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();
        const auto second=storage.dispatch("accounts.create",{{"username","room-b"},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();
        { std::ofstream file(root/"bootstrap.json"); file << config(); check(file.good(),"fixture_write_failed"); }
        LobbyRuntime runtime(storage,root/"bootstrap.json",[](const std::string&,const Json&){});
        const auto port=runtime.status().at("lobbyPort").get<std::uint16_t>();
        Peer a(port,11,"room-a"); a.send({34,words({first})}); a.until(70); a.send({7,words({0})}); a.until(30);
        Peer b(port,13,"room-b"); b.send({34,words({second})}); b.until(70); b.send({7,words({0})}); b.until(30);
        a.send({3,room_request()});
        const auto created=a.until(10);
        check(created.payload.size() == 224,"created_record_wrong_length");
        const auto room=read_le(View(created.payload).first(4));
        check(read_le(View(created.payload).subspan(68,4)) == first,"creation_self_predicate_wrong");
        const auto advertised=b.until(10);
        check(read_le(View(advertised.payload).first(4)) == room,"idle_room_catalog_missing");
        check(read_le(View(advertised.payload).subspan(68,4))==first,"remote_create_owner_missing");
        auto edited=room_request();
        put(edited,32,0x40); put(edited,60,first); put(edited,64,0);
        edited[128+5]='2';
        auto edit_body=words({room}); edit_body.insert(edit_body.end(),edited.begin(),edited.end());
        a.send({23,edit_body});
        const auto edit_a=a.until(26),edit_b=b.until(26);
        check(edit_a.payload==edit_body && edit_b.payload==edit_body,"canonical_map_edit_not_broadcast");
        b.send({4,words({room,1,1})});
        verify_pair(b.until(12),second,room); verify_pair(a.until(12),second,room);
        a.send({10,words({8})});
        const auto model_a=a.until(18),model_b=b.until(18);
        check(model_a.payload==words({first,8}) && model_b.payload==model_a.payload,"model_selection_not_broadcast");
        check(storage.roles_for_username("room-a").at(0).at("model")==8,"model_selection_not_persisted");
        a.send({5,{}}); verify_pair(a.until(13),first,room); verify_pair(b.until(13),first,room);
        a.send({60,{}}); verify_pair(a.until(96),first,room); verify_pair(b.until(96),first,room);
        b.send({6,words({1})}); verify_pair(b.until(14),second,room); verify_pair(a.until(14),second,room);
        a.close();
        verify_pair(b.until(14),first,room);
        const auto removed_room=b.receive();
        check(removed_room.wire_type == 57 && removed_room.payload == words({room}),"room_removal_order_wrong");
        const auto offline=b.receive();
        check(offline.wire_type == 55 && offline.payload == words({first}),"profile_removed_before_room_or_missing");
        b.close(); runtime.stop();
        check(!runtime.status().at("lobbyReady").get<bool>(),"runtime_stop_failed");
        runtime_game_flow(storage,root/"bootstrap.json",first);
        rejected_game_start_keeps_room_connected(root);
        first_login_registers_and_reuses_persistent_credentials(root);
        three_channel_tcp_isolation(root);
        std::cout << "PASS SQLite encrypted TCP rooms and first-login registration/persistent credential policy\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
