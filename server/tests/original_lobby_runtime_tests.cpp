#include "lobby_runtime.hpp"
#include "original_bank_fixture.hpp"
#include "original_exchange_test_scenario.hpp"
#include "original_runtime_test_io.hpp"
#include "original_room_runtime_scenario.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace {
using namespace richnet;
using Json = nlohmann::json;
using namespace original_runtime_test;
struct Scratch {
    std::filesystem::path path;
    Scratch() {
        const auto root = std::filesystem::temp_directory_path() / L"original-lobby-runtime-tests";
        for (std::uint32_t i=1;i<10000;++i) {
            path = root / std::to_wstring(i);
            if (std::filesystem::create_directories(path)) return;
        }
        throw std::runtime_error("scratch_exhausted");
    }
    ~Scratch() { std::error_code error; std::filesystem::remove_all(path,error); }
};
Json fixture() {
    Json config{{"version",1},{"client_profile","original"},
        {"provenance","Synthetic original runtime test only; opaque bytes are not production defaults."},
        {"room_id",3},{"game_capacity",8},{"player_capacity",100},{"item_grid_count",32},{"item_per_space",2},
        {"stage_progress_hex","01010200"},{"setting_text","4096"},{"tutorial_dismissal_mask",14},
        {"network",{{"bind_host","127.0.0.1"},{"lobby_port",0}}}};
    for (const auto& [key,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"room_template_hex",220},{"role_template_hex",208},{"profile_template_hex",268},
        {"login_template_hex",16},{"identity_template_hex",16},{"bank_template_hex",32},{"completion_template_hex",28}})
        config[key] = std::string(size*2,'a');
    config["bank_template_hex"] = original_bank_test::config_hex;
    constexpr std::string_view source = __FILE__;
    const auto options = (std::filesystem::path(std::u8string(source.begin(),source.end())).parent_path().parent_path().parent_path()/"Data"/"Option.kpd").u8string();
    config["client_options_path"] = std::string(options.begin(),options.end());
    const auto maps = (std::filesystem::path(std::u8string(source.begin(),source.end())).parent_path().parent_path().parent_path()/
        "protocol-analysis"/"board-startup"/"maps"/"index.json").u8string();
    config["map_catalog_path"] = std::string(maps.begin(),maps.end());
    return config;
}
void write(const std::filesystem::path& path,const Json& config) {
    std::ofstream file(path,std::ios::binary); file << config.dump();
    check(file.good(),"test_fixture_write_failed");
}
Bytes id_bytes(std::uint32_t id) { Bytes bytes; append_le(bytes,id,4); return bytes; }
std::uint32_t u32(const Bytes& bytes,std::size_t offset) { return read_le(View(bytes).subspan(offset,4)); }
void rejected_bootstraps(Storage& storage,const std::filesystem::path& root) {
    const auto log = [](const std::string&,const Json&) {};
    auto config = fixture(); config["client_profile"] = "richonline";
    write(root/L"wrong-profile.json",config);
    bool rejected = false;
    try { LobbyRuntime runtime(storage,root/L"wrong-profile.json",log); }
    catch (const CodecError& error) { rejected = std::string_view(error.what()) == "original_policy_profile_mismatch"; }
    check(rejected,"wrong_profile_bootstrap_accepted");
    config = fixture(); config["profile_template_hex"] = std::string(272*2,'a');
    write(root/L"wrong-layout.json",config);
    rejected = false;
    try { LobbyRuntime runtime(storage,root/L"wrong-layout.json",log); }
    catch (const CodecError& error) { rejected = std::string_view(error.what()) == "original_policy_hex_length_invalid"; }
    check(rejected,"new_client_profile_layout_accepted");
}
void login_and_select(Socket& client,const Json& account) {
    check(client.read(20) == Bytes({0x43,2,0,0,20,0,0,0,5,0,0,0,251,0,0,0,64,0,0,0}),"runtime_handshake_wrong");
    client.send({759,id_bytes(113)},std::nullopt);
    Bytes login;
    append_le(login,0x12345678,4); append_le(login,132,4); append_le(login,0,4);
    login.resize(144,0xca);
    const auto username = client_text(account.at("username").get<std::string>(),ClientProfile::original);
    const auto password = client_text("\xe5\xaf\x86\xe7\xa0\x81",ClientProfile::original);
    std::copy(username.begin(),username.end(),login.begin()+12); login[12+username.size()] = 0;
    std::copy(password.begin(),password.end(),login.begin()+76); login[76+password.size()] = 0;
    client.send({58,login});
    const auto role_id = account.at("role_id").get<std::uint32_t>();
    const auto catalog = client.receive();
    check(catalog.wire_type == 67 && catalog.payload.size() == 212 && u32(catalog.payload,0) == 1 &&
          u32(catalog.payload,4) == role_id,"runtime_sqlite_catalog_wrong");
    const auto identity = client.receive();
    check(identity.wire_type == 1 && identity.payload.size() == 16 && u32(identity.payload,0) == role_id,"runtime_login_wrong");
    client.send({34,id_bytes(role_id)});
    for (const auto type : {3U,9U,7U,140U,4U,2U,100U,103U,106U,30U}) {
        const auto frame = client.receive();
        check(frame.wire_type == type,"runtime_bootstrap_order_wrong");
        if (type == 3) check(frame.payload.size() == 220,"runtime_room_layout_wrong");
        if (type == 7) check(frame.payload.size() == 268 && u32(frame.payload,0) == role_id,"runtime_profile_layout_wrong");
        if (type == 106) check(frame.payload == Bytes({'4','1','1','0',0}),"runtime_settings_wrong");
    }
}
void original_runtime_uses_native_adapter() {
    const Network network;
    const Scratch scratch;
    Storage storage(scratch.path/L"accounts.sqlite3",ClientProfile::original);
    const auto log = [](const std::string&,const Json&) {};
    LobbyRuntime disabled(storage,scratch.path/L"missing.json",log);
    const auto absent = disabled.status();
    check(absent.at("lobbyConfigured") == false && absent.at("lobbyReady") == false &&
          absent.at("httpReady") == false && absent.at("blackReady") == false,"missing_config_listener_enabled");
    rejected_bootstraps(storage,scratch.path);
    const auto account = storage.dispatch("accounts.create",{{"username","\xe5\x8e\x9f\xe7\x89\x88\xe8\xbf\x90\xe8\xa1\x8c"},
        {"password","\xe5\xaf\x86\xe7\xa0\x81"}}).at("account");
    auto config = fixture();
    const auto path = scratch.path/L"bootstrap.json";
    write(path,config);
    LobbyRuntime runtime(storage,path,log);
    const auto started = runtime.status();
    check(started.at("lobbyConfigured") == true && started.at("lobbyReady") == true &&
          started.at("httpReady") == false && started.at("blackReady") == false,"original_listener_readiness_wrong");
    check(!started.contains("httpPort") && !started.contains("blackPort") && started.at("authenticatedSessions") == 0,
          "original_auxiliary_listener_or_session_unexpected");
    const auto port = started.at("lobbyPort").get<std::uint16_t>();
    Socket client(port);
    login_and_select(client,account);
    client.send(original_exchange_test::request(2));
    const auto exchanged = client.receive(), refreshed = client.receive();
    check(exchanged.wire_type == 79 && exchanged.payload.size() == 24,"runtime_exchange_not_configured");
    original_exchange_test::balance(exchanged.payload,16,20);
    check(refreshed.wire_type == 23 && refreshed.payload.size() == 268,"runtime_exchange_profile_missing");
    original_exchange_test::balance(refreshed.payload,76,account.at("coins").get<double>()-2);
    original_exchange_test::balance(refreshed.payload,84,account.at("gold").get<double>()+20);
    check(runtime.status().at("authenticatedSessions") == 1,"runtime_authenticated_count_wrong");
    shared_room_runtime(client,port,storage,login_and_select);
    config["network"]["lobby_port"] = port;
    write(scratch.path/L"collision.json",config);
    bool collision_rejected = false;
    try { LobbyRuntime collision(storage,scratch.path/L"collision.json",log); }
    catch (const CodecError& error) { collision_rejected = std::string(error.what()).find("lobby_bind_failed") != std::string::npos; }
    check(collision_rejected && runtime.status().at("lobbyReady") == true,"collision_stopped_original_listener");
    runtime.stop(); runtime.stop();
    const auto stopped = runtime.status();
    check(stopped.at("lobbyReady") == false && stopped.at("httpReady") == false && stopped.at("blackReady") == false &&
          stopped.at("lobbyPort") == 0 && stopped.at("authenticatedSessions") == 0,"original_runtime_stop_failed");
    char byte{};
    check(recv(client.value,&byte,1,0) == 0,"runtime_stop_left_peer_open");
    config["network"]["lobby_port"] = 0;
    config["network"]["auxiliary"] = {{"advertised_host","127.0.0.1"},{"http_port",0},{"black_port",0}};
    write(path,config);
    {
        LobbyRuntime enabled(storage,path,log);
        const auto state = enabled.status();
        check(state.at("lobbyReady") == true && state.at("httpReady") == true && state.at("blackReady") == true,
              "original_auxiliary_not_ready");
        Socket player(state.at("lobbyPort").get<std::uint16_t>());
        login_and_select(player,account);
        const auto document = http(state.at("httpPort").get<std::uint16_t>());
        for (const auto& field : {std::string("\nChannelID=3\n"),std::string("\nLobbyType=0\n"),
            std::string("\nNowPlayerNum=1\n"),"\nPort="+state.at("lobbyPort").dump()+"\n"})
            check(document.find(field) != std::string::npos,"original_http_discovery_field_wrong");
        Socket black(state.at("blackPort").get<std::uint16_t>());
        black.raw(black_request(1));
        const auto added = black_reply(black);
        check(added.size() == 36 && u32(added,0) == 0 && added[4] == 'B',"runtime_black_add_failed");
        auto collision_config = config;
        collision_config["network"]["auxiliary"]["black_port"] = state.at("blackPort");
        write(scratch.path/L"aux-collision.json",collision_config);
        bool rejected = false;
        try { LobbyRuntime collision(storage,scratch.path/L"aux-collision.json",log); }
        catch (const CodecError& error) { rejected = std::string(error.what()).find("auxiliary_bind_failed") != std::string::npos; }
        check(rejected && enabled.status().at("blackReady") == true,"auxiliary_collision_stopped_existing_runtime");
        enabled.stop();
        const auto off = enabled.status();
        check(off.at("lobbyPort") == 0 && off.at("httpPort") == 0 && off.at("blackPort") == 0 &&
              off.at("lobbyReady") == false && off.at("httpReady") == false && off.at("blackReady") == false,
              "auxiliary_stop_left_listeners_active");
    }
    check(std::filesystem::exists(scratch.path/L"original-blacklist.sqlite3"),"runtime_blacklist_database_path_wrong");
    LobbyRuntime reopened(storage,path,log);
    Socket black(reopened.status().at("blackPort").get<std::uint16_t>());
    black.raw(black_request(0));
    const auto entry = black_reply(black), end = black_reply(black);
    check(entry.size() == 33 && entry[0] == 'B' && entry[32] == 1 && end == Bytes(33,0),
          "runtime_blacklist_restart_lost_entry");
    reopened.stop();
}
}
int main() {
    try {
        original_runtime_uses_native_adapter();
        std::cout << "original native runtime tests PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
