#pragma once
#include "lobby_runtime.hpp"
#include "original_bank_fixture.hpp"
#include "original_runtime_test_io.hpp"
#include "original_room_runtime_scenario.hpp"
#include "original_game_startup_test_support.hpp"
#include <fstream>

namespace original_handoff_test {
using namespace richnet;
using Json = nlohmann::json;
using original_runtime_test::Socket;
using original_runtime_test::check;
namespace game = original_startup_test;
struct Scratch {
    std::filesystem::path path;
    Scratch() {
        const auto root = std::filesystem::temp_directory_path()/L"original-handoff-tcp-tests";
        for (std::uint32_t i = 1; i < 10000; ++i) {
            path = root/std::to_wstring(i);
            if (std::filesystem::create_directories(path)) return;
        }
        throw std::runtime_error("handoff_scratch_exhausted");
    }
    ~Scratch() { std::error_code error; std::filesystem::remove_all(path,error); }
};
inline Bytes words(std::initializer_list<std::uint32_t> values) {
    Bytes bytes; for (const auto value : values) append_le(bytes,value,4); return bytes;
}
inline void bootstrap(const std::filesystem::path& path) {
    Json config{{"version",1},{"client_profile","original"},
        {"provenance","Synthetic handoff fixture; startup/actions are not a playable BOSS strategy."},
        {"room_id",3},{"game_capacity",8},{"player_capacity",100},{"item_grid_count",32},{"item_per_space",2},
        {"stage_progress_hex","01010200"},{"setting_text","4096"},{"tutorial_dismissal_mask",14},
        {"network",{{"bind_host","127.0.0.1"},{"lobby_port",0}}}};
    for (const auto& [key,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"room_template_hex",220},{"role_template_hex",208},{"profile_template_hex",268},
        {"login_template_hex",16},{"identity_template_hex",16},{"bank_template_hex",32},{"completion_template_hex",28}})
        config[key] = std::string(size*2,'a');
    config["bank_template_hex"] = original_bank_test::config_hex;
    constexpr std::u8string_view source = RICHONLINE_LEGACY_RESOURCE_ROOT;
    const auto root = std::filesystem::path(std::u8string(source.begin(),source.end()));
    const auto options = (root/"Data"/"Option.kpd").u8string();
    const auto maps = (root/"protocol-analysis"/"board-startup"/"maps"/"index.json").u8string();
    config["client_options_path"] = std::string(options.begin(),options.end());
    config["map_catalog_path"] = std::string(maps.begin(),maps.end());
    std::ofstream file(path,std::ios::binary); file << config.dump(); check(file.good(),"handoff_bootstrap_write_failed");
}
inline void login(Socket& client, const Json& account) {
    check(client.read(20) == Bytes({0x43,2,0,0,20,0,0,0,5,0,0,0,251,0,0,0,64,0,0,0}),"handoff_handshake_wrong");
    client.send({759,words({113})},std::nullopt);
    Bytes data = words({0x12345678,132,0}); data.resize(144,0xca);
    const auto username = client_text(account.at("username").get<std::string>(),ClientProfile::original);
    const auto password = client_text("handoff-password",ClientProfile::original);
    std::copy(username.begin(),username.end(),data.begin()+12); data[12+username.size()] = 0;
    std::copy(password.begin(),password.end(),data.begin()+76); data[76+password.size()] = 0;
    client.send({58,data});
    const auto catalog = client.receive(), identity = client.receive();
    check(catalog.wire_type == 67 && identity.wire_type == 1,"handoff_login_failed");
    client.send({34,words({account.at("role_id").get<std::uint32_t>()})});
    for (const auto type : {3U,9U,7U,140U,4U,2U,100U,103U,106U,30U})
        check(client.receive().wire_type == type,"handoff_lobby_bootstrap_wrong");
}
inline std::uint32_t create(Socket& client) {
    client.send({3,original_runtime_test::room_description(false)});
    const auto frame = client.receive();
    check(frame.wire_type == 10 && frame.payload.size() == 216,"handoff_create_failed");
    return read_le(View(frame.payload).first(4));
}
inline Frame configuration(Socket& client, std::uint32_t room, bool running) {
    auto frame = client.receive();
    check(frame.wire_type == 26 && frame.payload.size() == 212 && read_le(View(frame.payload).first(4)) == room,
        "handoff_configuration_wrong");
    check(((read_le(View(frame.payload).subspan(36,4)) & 0x800U) != 0) == running,"handoff_running_flag_wrong");
    return frame;
}
inline GameAdmission ready(Socket& client, std::uint32_t room, std::uint32_t user, std::uint16_t port) {
    client.send({5,{}});
    const auto prepared = client.receive();
    check(prepared.wire_type == 13 && prepared.payload == words({user,room}),"handoff_ready_missing");
    configuration(client,room,true);
    const auto redirect = client.receive();
    check(redirect.wire_type == 22 && redirect.payload.size() == 18,"handoff_redirect_missing");
    const View bytes(redirect.payload);
    check(bytes[0] == 127 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 1 && read_le(bytes.subspan(4,2)) == port,
        "handoff_redirect_endpoint_wrong");
    GameAdmission result{3,room,user,{},read_le(bytes.subspan(6,4)),std::array<std::uint32_t,2>{0,0}};
    std::copy(bytes.begin()+10,bytes.end(),result.opaque8.begin());
    check(encode_game_admission(result,ClientVersion::legacy).payload.size() == 32,"handoff_original_admission_not32");
    return result;
}
inline void departed(Socket& client, std::uint32_t room, std::uint32_t user) {
    const auto frame = client.receive();
    check(frame.wire_type == 14 && frame.payload == words({user,room,0xffffffffU}),"handoff_lobby_departure_missing");
}
}
