#include "richonline_boss_host.hpp"
#include "server_lobby_adapter.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <limits>
#include <utility>

namespace richnet {
namespace {
using Json = nlohmann::json;
void fields(const Json& object, std::initializer_list<std::string_view> names) {
    if (!object.is_object() || object.size() != names.size()) throw CodecError("richonline_boss_host_config_fields_invalid");
    for (const auto name : names) if (!object.contains(name)) throw CodecError("richonline_boss_host_config_fields_invalid");
}
std::int64_t number(const Json& value, std::int64_t minimum, std::int64_t maximum) {
    if (!value.is_number_integer() || value < minimum || value > maximum) throw CodecError("richonline_boss_host_number_invalid");
    return value.get<std::int64_t>();
}
std::string provenance(const Json& value) {
    if (!value.is_string()) throw CodecError("richonline_boss_host_provenance_required");
    auto text = value.get<std::string>();
    if (text.size() < 8 || text.size() > 4096 || text.find('\0') != text.npos) throw CodecError("richonline_boss_host_provenance_required");
    return text;
}
template<class T, std::size_t N> std::array<T,N> numbers(const Json& value, std::int64_t minimum, std::int64_t maximum) {
    if (!value.is_array() || value.size() != N) throw CodecError("richonline_boss_host_array_invalid");
    std::array<T,N> result;
    for (std::size_t i = 0; i < N; ++i) result[i] = static_cast<T>(number(value[i],minimum,maximum));
    return result;
}
std::array<std::uint8_t,8> f64(const Json& value) {
    if (!value.is_string()) throw CodecError("richonline_boss_host_f64_hex_invalid");
    const auto text = value.get<std::string>();
    if (text.size() != 16) throw CodecError("richonline_boss_host_f64_hex_invalid");
    const auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c-'0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c-'a'+10);
        if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c-'A'+10);
        throw CodecError("richonline_boss_host_f64_hex_invalid");
    };
    std::array<std::uint8_t,8> result;
    for (std::size_t i = 0; i < 8; ++i) result[i] = static_cast<std::uint8_t>((nibble(text[2*i]) << 4) | nibble(text[2*i+1]));
    return result;
}
struct Policy {
    std::filesystem::path resources;
    std::array<std::uint8_t,4> address;
    std::uint16_t port;
    std::chrono::milliseconds ttl;
    RichonlineBossWirePolicy wire;
    std::string source, wire_source;
};
Policy policy(const Json& config, const std::filesystem::path& bootstrap) {
    fields(config,{"version","provenance","client_root","advertised_ipv4","port","manager","admission_ttl_ms",
        "spawn_policy","token_policy","filler_policy","wire"});
    if (number(config.at("version"),1,1) != 1 || number(config.at("manager"),0,65535) != 0 ||
        config.at("spawn_policy") != "resource-straight-road-farthest-v1" ||
        config.at("token_policy") != "system-random-echo" || config.at("filler_policy") != "system-random-unconsumed")
        throw CodecError("richonline_boss_host_policy_unsupported");
    const auto root = config.at("client_root").get<std::string>();
    if (root.empty() || root.find('\0') != root.npos) throw CodecError("richonline_boss_host_resource_path_invalid");
    std::filesystem::path path(std::u8string(root.begin(),root.end()));
    if (path.is_relative()) path = std::filesystem::absolute(bootstrap).parent_path()/path;
    path = path.lexically_normal();
    if (!std::filesystem::is_regular_file(path/"Data/Prop.kpd"))
        throw CodecError("richonline_boss_host_resource_missing");
    const auto& wire = config.at("wire");
    fields(wire,{"provenance","game_server_id","calendar_counter","year","month","day","weekday","opaque_f64_hex",
        "opaque_header_byte","opaque_trailing","synthetic_unconsumed_skill_bytes","envelope"});
    const auto& envelope = wire.at("envelope"); fields(envelope,{"tag","mode"});
    RichonlineBossWirePolicy selected{
        static_cast<std::uint16_t>(number(wire.at("game_server_id"),0,65535)),
        static_cast<std::uint32_t>(number(wire.at("calendar_counter"),0,std::numeric_limits<std::uint32_t>::max())),
        static_cast<std::int16_t>(number(wire.at("year"),-32767,32767)),
        static_cast<std::uint8_t>(number(wire.at("month"),1,12)), static_cast<std::uint8_t>(number(wire.at("day"),1,31)),
        static_cast<std::uint8_t>(number(wire.at("weekday"),1,7)), f64(wire.at("opaque_f64_hex")),
        static_cast<std::uint8_t>(number(wire.at("opaque_header_byte"),0,255)),
        numbers<std::uint8_t,2>(wire.at("opaque_trailing"),0,255),
        numbers<std::int8_t,10>(wire.at("synthetic_unconsumed_skill_bytes"),-128,127),
        {static_cast<std::int16_t>(number(envelope.at("tag"),-32768,32767)),
         static_cast<std::int8_t>(number(envelope.at("mode"),-128,127))}};
    if (!std::chrono::year_month_day{std::chrono::year{selected.year},std::chrono::month{selected.month},std::chrono::day{selected.day}}.ok())
        throw CodecError("richonline_boss_host_calendar_invalid");
    return {std::move(path),numbers<std::uint8_t,4>(config.at("advertised_ipv4"),0,255),
        static_cast<std::uint16_t>(number(config.at("port"),0,65535)),
        std::chrono::milliseconds(number(config.at("admission_ttl_ms"),1,300000)),selected,
        provenance(config.at("provenance")),provenance(wire.at("provenance"))};
}
Bytes random_bytes(std::size_t size) {
    if (size > std::numeric_limits<ULONG>::max()) throw CodecError("richonline_boss_host_random_size_invalid");
    Bytes result(size);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr,result.data(),static_cast<ULONG>(size),BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        throw CodecError("richonline_boss_host_random_failed");
    return result;
}
void validate_strategy(const RichonlineStartupPlan& strategy, const RichonlineBossStartup& startup) {
    try {
        if (!strategy.map_ready || !strategy.action || !strategy.disconnected)
            throw CodecError("richonline_boss_host_strategy_incomplete");
        if (encode_richonline_board_init(strategy.init) != encode_richonline_board_init(startup.init) ||
            encode_richonline_board_snapshot(strategy.snapshot) != encode_richonline_board_snapshot(startup.snapshot) ||
            strategy.envelope.tag != startup.envelope.tag || strategy.envelope.mode != startup.envelope.mode)
            throw CodecError("richonline_boss_host_strategy_initialization_changed");
    } catch (...) {
        if (strategy.disconnected) { try { strategy.disconnected(); } catch (...) {} }
        throw;
    }
}
struct SelectedMapIdentity {
    std::string name;
    std::uint32_t category;
};
SelectedMapIdentity selected_map_identity(View extension) {
    if (extension.size()!=88) throw CodecError("richonline_boss_E88_invalid");
    const auto end=std::find(extension.begin(),extension.begin()+32,std::uint8_t{0});
    if (end==extension.begin() || end==extension.begin()+32)
        throw CodecError("richonline_stage_map_unsupported");
    // The validated E88 category is a full DWORD; only value 2 selects special maps.
    return {std::string(extension.begin(),end),read_le(extension.subspan(68,4))};
}
}
std::optional<RichonlineRuntimeGame> load_richonline_boss_host(Storage& storage,
    const std::filesystem::path& bootstrap, ControlLog log, RichonlineBossStrategyFactory strategy) {
    if (!std::filesystem::exists(bootstrap)) return {};
    std::ifstream stream(bootstrap,std::ios::binary);
    if (!stream) throw CodecError("bootstrap_file_open_failed");
    try {
        const auto config = Json::parse(stream);
        if (!config.is_object()) throw CodecError("richonline_boss_host_config_fields_invalid");
        if (!config.contains("richonline_boss_game")) return {};
        if (storage.client_profile() != ClientProfile::richonline) throw CodecError("richonline_boss_host_client_profile_invalid");
        if (!strategy) throw CodecError("richonline_boss_host_strategy_required");
        auto selected = policy(config.at("richonline_boss_game"),bootstrap);
        const auto blobs = load_bootstrap_blobs(bootstrap);
        if (!blobs.room_unknown_prefix) throw CodecError("richonline_boss_host_rooms_required");
        if (log) log("richonline_boss_host_configured",{{"provenance",selected.source},{"wire_provenance",selected.wire_source},
            {"scope","boss-selected-map-startup"},{"runtime_client_verified",false},{"game_ready",false}});
        const auto listen_port = selected.port; const auto ttl = selected.ttl;
        return RichonlineRuntimeGame{listen_port,0,ttl,
            [&storage, selected = std::move(selected), capacity = blobs.player_capacity,
             strategy = std::move(strategy), log = std::move(log)](std::uint16_t bound_port,const RichonlineRoomSnapshot& room) {
                if (bound_port == 0) throw CodecError("richonline_boss_host_bound_port_invalid");
                if (room.owner == 0 || room.owner >= capacity || room.owner > 32767)
                    throw CodecError("richonline_boss_host_actor_out_of_range");
                const auto settings = storage.dispatch("config.get",Json::object());
                const auto skills = numbers<std::int8_t,10>(settings.at("settings").at("max_building_skills"),0,7);
                const auto now=std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                const auto inventory=storage.lobby_inventory_for_role(room.owner,now);
                const auto startup = build_richonline_boss_startup(selected.resources,room,
                    {static_cast<std::int16_t>(room.owner),inventory.equipment,skills,selected.wire});
                const auto map=selected_map_identity(startup.room.description.extension);
                const auto entropy = random_bytes(12);
                RichonlineGameRedirect redirect{selected.address,bound_port,read_le(View(entropy).first(4)),{}};
                std::copy_n(entropy.begin()+4,8,redirect.token.begin());
                const auto admission = richonline_expected_admission({room.channel,room.key,room.owner},redirect);
                auto plan = strategy(startup); validate_strategy(plan,startup);
                const auto sent_enabled=static_cast<bool>(plan.sent);
                const auto game_finished=plan.game_finished;
                const auto lobby_sent=plan.lobby_sent;
                const auto terminal_pending=plan.terminal_pending;
                auto callbacks = make_richonline_game_callbacks(
                    [plan = std::optional<RichonlineStartupPlan>(std::move(plan))](const GameAdmission&) mutable {
                        return std::exchange(plan,{});
                    },random_bytes,[log, key = room.key,channel=room.channel](const std::string& message) {
                        if (log) log("richonline_boss_startup",{{"channel",channel},{"room",key},{"message",message}});
                    });
                if (!callbacks.authorize_admission(admission)) throw CodecError("richonline_boss_host_plan_authorization_failed");
                if (log) log("richonline_boss_plan_prepared",{{"channel",room.channel},{"room",room.key},{"actor",room.owner},
                    {"settings_revision",settings.at("revision")},{"map",map.name},{"category",map.category},{"game_server_id",selected.wire.game_server_id},
                    {"calendar_counter",selected.wire.calendar_counter},{"runtime_client_verified",false}});
                return std::vector<RichonlineGamePlan>{{room.participants.front().connection,room.owner,redirect,
                    [callbacks,admission] { return callbacks.admitted(admission); },
                    [callbacks,admission](const Envelope299& envelope,View plain) { return callbacks.message(admission,envelope,plain); },
                    [callbacks,admission] { callbacks.disconnected(admission); },
                    [callbacks,admission] { return callbacks.poll(admission); },
                    sent_enabled ? std::function<void(const Frame&)>{[callbacks,admission](const Frame& frame) {
                        callbacks.sent(admission,frame);
                    }} : std::function<void(const Frame&)>{},game_finished,lobby_sent,terminal_pending}};
            }};
    } catch (const Json::exception&) { throw CodecError("richonline_boss_host_json_invalid"); }
}
}
