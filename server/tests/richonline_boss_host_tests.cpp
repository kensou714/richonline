#include "richonline_boss_host.hpp"
#include "original_map.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void check(bool value, std::string_view code) { if (!value) throw std::runtime_error(std::string(code)); }
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code, error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
void put(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) bytes.at(offset+i) = static_cast<std::uint8_t>(value >> (8*i));
}
Json configuration(const std::filesystem::path& resources) {
    const auto path = std::filesystem::absolute(resources).u8string();
    Json config{{"provenance","Isolated real-resource host test; not a native-client gameplay result."},
        {"game_capacity",8},{"player_capacity",100},{"stage_progress",{1,1,2,0}},{"setting_text","14"},
        {"room_unknown_prefix",9},
        {"richonline_boss_game",{{"version",1},{"provenance","Explicit isolated host test policy."},
            {"client_root",std::string(path.begin(),path.end())},{"advertised_ipv4",{127,0,0,1}},
            {"port",0},{"manager",0},{"admission_ttl_ms",30000},
            {"spawn_policy","resource-straight-road-farthest-v1"},
            {"token_policy","system-random-echo"},{"filler_policy","system-random-unconsumed"},
            {"wire",{{"provenance","f64 constructor baseline; remaining values explicit test policy."},
                {"game_server_id",123},{"calendar_counter",456},{"year",2026},{"month",10},{"day",9},{"weekday",5},
                {"opaque_f64_hex","000000000000f03f"},{"opaque_header_byte",0xa1},
                {"opaque_trailing",{0xb1,0xb2}},{"synthetic_unconsumed_skill_bytes",{1,2,3,4,5,6,7,8,9,10}},
                {"envelope",{{"tag",-3},{"mode",-4}}}}}}}};
    for (const auto& [name,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"unknown_channel_record_hex",80},{"unknown_role_record_hex",208},{"unknown_profile_record_hex",272},
        {"unknown_login_result_hex",16},{"unknown_identity_record_hex",16},{"unknown_empty_list_hex",4},
        {"unknown_bank_config_hex",32}}) config[name] = std::string(size*2,'0');
    config["unknown_completion_hex"] = std::string(40,'0')+"000000000000f03f";
    return config;
}
struct Fixture {
    std::filesystem::path root = std::filesystem::absolute("richonline-host-test-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::path file = root/"bootstrap.json";
    Storage storage{root/"accounts.sqlite3"};
    std::uint32_t actor = storage.dispatch("accounts.create",{{"username","host-fixture"},{"password","test-only"}})
        .at("account").at("role_id").get<std::uint32_t>();
    void save(const Json& value) const {
        std::ofstream output(file); output << value;
        check(output.good(),"fixture_write_failed");
    }
};
RichonlineRoomSnapshot room(const std::filesystem::path& resources, std::uint32_t actor,
    std::string_view name="BS_1_1.emp",std::uint32_t category=0,std::uint32_t pawn_gold=100) {
    RichonlineRoomSnapshot value{3,actor,{},{{77,actor,0,true}}};
    auto& e = value.description.extension;
    e = Bytes(88,0);
    std::copy(name.begin(),name.end(),e.begin());
    const auto emp = load_original_emp(resources/"Map"/name);
    std::copy(emp.signature.begin(),emp.signature.end(),e.begin()+32);
    put(e,48,3); put(e,52,1); put(e,56,10); put(e,60,3); put(e,64,pawn_gold); put(e,68,category);
    e[73] = 0xa7; e[85] = 0xb8;
    value.description.record[32] = 0x40; value.description.record[36] = 3;
    value.description.record[40] = 1; value.description.record[120] = 88; value.description.record[124] = 1;
    return value;
}
RichonlineStartupPlan test_strategy(const RichonlineBossStartup& startup) {
    return {startup.init,startup.snapshot,startup.envelope,[] { return std::vector<Bytes>{}; },
        [](const Envelope299&,View) { return std::vector<Bytes>{}; },[] {}};
}
void optional_configuration_and_strict_policy(const std::filesystem::path& resources) {
    Fixture fixture;
    check(!load_richonline_boss_host(fixture.storage,fixture.file,{}),"missing_file_enables_game");
    auto config = configuration(resources), absent = config; absent.erase("richonline_boss_game");
    fixture.save(absent);
    check(!load_richonline_boss_host(fixture.storage,fixture.file,{}),"missing_policy_enables_game");
    fixture.save(config);
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{}); },"richonline_boss_host_strategy_required");
    for (const auto& field : {"opaque_header_byte","opaque_trailing","synthetic_unconsumed_skill_bytes","opaque_f64_hex"}) {
        auto bad = config; bad["richonline_boss_game"]["wire"].erase(field); fixture.save(bad);
        rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_config_fields_invalid");
    }
    auto bad = config; bad["richonline_boss_game"]["unexpected"] = 1; fixture.save(bad);
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_config_fields_invalid");
    bad = config; bad["richonline_boss_game"]["wire"]["month"] = 2; bad["richonline_boss_game"]["wire"]["day"] = 30;
    fixture.save(bad);
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_calendar_invalid");
    bad = config; bad["richonline_boss_game"]["manager"] = 1; fixture.save(bad);
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_policy_unsupported");
    bad = config; bad.erase("room_unknown_prefix"); fixture.save(bad);
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_rooms_required");
    for (const auto& [field,value] : std::initializer_list<std::pair<const char*,Json>>{
        {"port",65536},{"admission_ttl_ms",0},{"admission_ttl_ms",300001}}) {
        bad = config; bad["richonline_boss_game"][field] = value; fixture.save(bad);
        rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_number_invalid");
    }
    for (const auto& [field,value] : std::initializer_list<std::pair<const char*,Json>>{
        {"game_server_id",65536},{"calendar_counter",4294967296ULL},{"opaque_header_byte",-1},{"year",-32768}}) {
        bad = config; bad["richonline_boss_game"]["wire"][field] = value; fixture.save(bad);
        rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_number_invalid");
    }
    bad = config; bad["richonline_boss_game"]["wire"]["opaque_f64_hex"] = "000000000000f03g"; fixture.save(bad);
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_f64_hex_invalid");
    bad = config; bad["richonline_boss_game"]["wire"]["provenance"] = ""; fixture.save(bad);
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },"richonline_boss_host_provenance_required");
}
void unsupported_room_and_strategy_mismatch_cleanly_fail(const std::filesystem::path& resources) {
    Fixture fixture; fixture.save(configuration(resources)); int cleaned = 0, built = 0;
    auto host = load_richonline_boss_host(fixture.storage,fixture.file,{},[&](const RichonlineBossStartup& startup) {
        ++built; auto strategy = test_strategy(startup); strategy.snapshot.slots[0].cash = 1;
        strategy.disconnected = [&] { ++cleaned; }; return strategy;
    });
    const auto actual = room(resources,fixture.actor);
    rejects([&] { host->provider(0,actual); },"richonline_boss_host_bound_port_invalid");
    auto invalid = actual; invalid.owner = 32768;
    rejects([&] { host->provider(19001,invalid); },"richonline_boss_host_actor_out_of_range");
    invalid = actual; invalid.description.extension[32] ^= 1;
    rejects([&] { host->provider(19001,invalid); },"richonline_boss_map_signature_mismatch");
    invalid = actual; invalid.description.extension.pop_back();
    rejects([&] { host->provider(19001,invalid); },"richonline_boss_E88_invalid");
    check(built == 0 && cleaned == 0,"invalid_room_reached_strategy");
    rejects([&] { host->provider(19001,actual); },"richonline_boss_host_strategy_initialization_changed");
    check(built == 1 && cleaned == 1,"rejected_strategy_not_cleaned");
}
void real_resources_sqlite_revision_and_admission(const std::filesystem::path& resources) {
    Fixture fixture; fixture.save(configuration(resources));
    int loaded = 0, cleaned = 0, polled = 0; std::vector<RichonlineBossStartup> built; std::vector<Json> logs;
    auto host = load_richonline_boss_host(fixture.storage,fixture.file,
        [&](const std::string& event,const Json& data) { logs.push_back({{"event",event},{"data",data}}); },
        [&](const RichonlineBossStartup& startup) {
            built.push_back(startup);
            return RichonlineStartupPlan{startup.init,startup.snapshot,startup.envelope,
                [&] { ++loaded; return std::vector<Bytes>{}; },
                [](const Envelope299&,View) { return std::vector<Bytes>{}; },[&] { ++cleaned; },
                [&] { ++polled; return std::vector<Bytes>{{0x20,0x40,123,0,0}}; }};
        });
    check(host && host->port == 0 && host->manager == 0 && host->admission_ttl == std::chrono::seconds(30),"host_options_lost");
    const auto actual = room(resources,fixture.actor);
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& value) { return host->provider(19001,value); },host->manager,host->admission_ttl);
    const auto redirects = registry.prepare(actual);
    check(redirects.size() == 1 && redirects.front().frame.wire_type == 22 && redirects.front().recipient == 77,"admission_redirect_missing");
    const auto& payload = redirects.front().frame.payload;
    GameAdmission admission{0,actual.key,fixture.actor,{},read_le(View(payload).subspan(6,4)),{}};
    std::copy(payload.begin()+10,payload.end(),admission.opaque8.begin());
    auto callbacks = registry.callbacks();
    auto wrong = admission; wrong.opaque8[0] ^= 1;
    check(!callbacks.authorize_admission(wrong) && callbacks.authorize_admission(admission),"full_admission_binding_failed");
    auto replay = registry.callbacks(); check(!replay.authorize_admission(admission),"admission_replay_accepted");
    const auto initial = callbacks.admitted(admission);
    check(initial.size() == 2 && initial[0].wire_type == 1 && initial[0].payload.empty(),"admission_ack_must_precede_init");
    const auto init = decode_inner(decode_envelope(initial[1],ClientVersion::richonline).encoded);
    check(init.size() == 52 && init[25] == 7 && init[19] == 0xa1 && built.front().init.participants[0].position == 115 &&
        built.front().init.participants[1].position == 236 && built.front().room.description.extension == actual.description.extension,
        "resource_or_explicit_policy_lost");
    const Envelope299 envelope{0,-1,{},{}};
    check(static_cast<bool>(callbacks.poll),"host_registry_poll_missing");
    check(callbacks.poll(admission).empty() && polled == 0,"poll_before_map_ready");
    check(callbacks.message(admission,envelope,Bytes{1,0}).empty() && loaded == 0,"init_signal_misread_as_map_ready");
    const auto sync = callbacks.message(admission,envelope,Bytes{0,0});
    const auto plain = decode_inner(decode_envelope(sync.front(),ClientVersion::richonline).encoded);
    check(sync.size() == 1 && plain.size() == 36 && read_le(View(plain).subspan(12,4)) == 20000 &&
        read_le(View(plain).subspan(24,4)) == 100000 && loaded == 1,"real_resource_snapshot_wrong");
    const auto polled_frames = callbacks.poll(admission);
    check(polled == 1 && polled_frames.size() == 1,"host_poll_not_forwarded");
    const auto polled_envelope = decode_envelope(polled_frames.front(),ClientVersion::richonline);
    check(polled_envelope.inner_type == -3 && polled_envelope.mode == -4 &&
        decode_inner(polled_envelope.encoded) == Bytes{0x20,0x40,123,0,0},"host_poll_envelope_wrong");
    callbacks.disconnected(admission); registry.shutdown(); check(cleaned == 1,"cleanup_not_exactly_once");
    rejects([&] { callbacks.poll(admission); },"richonline_game_plan_cancelled");
    check(polled == 1,"host_poll_after_cleanup");
    auto settings = fixture.storage.dispatch("config.get",Json::object());
    settings["settings"]["max_building_skills"][0] = 6;
    fixture.storage.dispatch("config.update",{{"expectedRevision",settings.at("revision")},{"settings",settings.at("settings")}});
    auto next = host->provider(19002,actual);
    check(built.size() == 2 && built[0].init.participants[0].building_skill_caps[0] == 7 &&
        built[1].init.participants[0].building_skill_caps[0] == 6,"per_game_settings_revision_not_frozen");
    next.front().disconnected(); check(cleaned == 2,"second_plan_cleanup_failed");
    check(std::any_of(logs.begin(),logs.end(),[](const Json& row) {
        return row.at("event") == "richonline_boss_plan_prepared" && row.at("data").at("settings_revision") == 2 &&
            row.at("data").at("map")=="BS_1_1.emp" && row.at("data").at("category")==0;
    }),"settings_revision_not_logged");
    auto raw_category=actual; put(raw_category.description.extension,68,0xffffffffU);
    auto raw_plan=host->provider(19002,raw_category); raw_plan.front().disconnected();
    check(std::any_of(logs.begin(),logs.end(),[](const Json& row) {
        return row.at("event")=="richonline_boss_plan_prepared" &&
            row.at("data").at("map")=="BS_1_1.emp" && row.at("data").at("category")==0xffffffffU;
    }),"raw_category_not_logged");
}
void special_only_resources_use_selected_map(const std::filesystem::path& resources) {
    Fixture fixture;
    const auto isolated=fixture.root/"special-only";
    std::filesystem::create_directories(isolated/"Data");
    std::filesystem::create_directories(isolated/"Map");
    for (const auto name:{"Data/Prop.kpd","Data/BossWar_v.kpd","Map/V_BS_1_1.emp"})
        std::filesystem::copy_file(resources/name,isolated/name);
    check(!std::filesystem::exists(isolated/"Map/BS_1_1.emp") &&
        !std::filesystem::exists(isolated/"Data/BossWar.kpd"),"ordinary_resources_leaked_into_fixture");
    fixture.save(configuration(isolated));
    std::vector<Json> logs; std::vector<RichonlineBossStartup> built;
    // This tests host preparation only; production runtime readiness remains the strategy's responsibility.
    auto host=load_richonline_boss_host(fixture.storage,fixture.file,
        [&](const std::string& event,const Json& data) { logs.push_back({{"event",event},{"data",data}}); },
        [&](const RichonlineBossStartup& startup) { built.push_back(startup); return test_strategy(startup); });
    check(host.has_value(),"special_only_host_not_configured");
    const auto selected=room(isolated,fixture.actor,"V_BS_1_1.emp",2,0);
    auto plans=host->provider(19003,selected);
    check(plans.size()==1 && built.size()==1 && built.front().room.description.extension==selected.description.extension &&
        built.front().init.participants[0].position==99 && built.front().init.participants[1].position==106 &&
        built.front().snapshot.slots[0].cash==12000 && built.front().snapshot.slots[0].tickets==350 &&
        built.front().snapshot.slots[1].cash==150000,"special_host_used_ordinary_initialization");
    plans.front().disconnected();
    check(std::any_of(logs.begin(),logs.end(),[](const Json& row) {
        return row.at("event")=="richonline_boss_host_configured" &&
            row.at("data").at("scope")=="boss-selected-map-startup" && !row.at("data").at("game_ready").get<bool>();
    }),"selected_map_scope_not_logged");
    check(std::any_of(logs.begin(),logs.end(),[](const Json& row) {
        return row.at("event")=="richonline_boss_plan_prepared" &&
            row.at("data").at("map")=="V_BS_1_1.emp" && row.at("data").at("category")==2;
    }),"special_map_identity_not_logged");
    std::filesystem::remove(isolated/"Map/V_BS_1_1.emp");
    check(load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy).has_value(),
        "selected_map_validated_before_room_selection");
    rejects([&] { host->provider(19003,selected); },"richonline_stage_map_resource_missing");
    check(built.size()==1,"missing_map_reached_strategy");
    std::filesystem::remove(isolated/"Data/Prop.kpd");
    rejects([&] { load_richonline_boss_host(fixture.storage,fixture.file,{},test_strategy); },
        "richonline_boss_host_resource_missing");
}
void real_host_uses_selected_channel_for_admission(const std::filesystem::path& resources) {
    Fixture fixture; fixture.save(configuration(resources)); std::array<int,3> cleaned{};
    auto host=load_richonline_boss_host(fixture.storage,fixture.file,{},[&](const RichonlineBossStartup& startup) {
        auto plan=test_strategy(startup);
        plan.disconnected=[&,channel=startup.room.channel] { ++cleaned.at(channel); };
        return plan;
    });
    RichonlineGameRegistry registry([&](const RichonlineRoomSnapshot& value) {
        return host->provider(19001,value);
    },host->manager,host->admission_ttl);
    std::array<GameAdmission,3> admissions;
    std::array<GameCallbacks,3> callbacks;
    for (std::uint32_t channel=0;channel<3;++channel) {
        auto selected=room(resources,fixture.actor); selected.channel=channel;
        selected.participants.front().connection+=channel;
        const auto response=registry.prepare(selected).front().frame.payload;
        admissions[channel]={channel,selected.key,fixture.actor,{},read_le(View(response).subspan(6,4)),{}};
        std::copy(response.begin()+10,response.end(),admissions[channel].opaque8.begin());
        callbacks[channel]=registry.callbacks();
        auto wrong=admissions[channel]; wrong.id0=(channel+1)%3;
        check(!callbacks[channel].authorize_admission(wrong),"host_other_channel_admission_accepted");
        check(callbacks[channel].authorize_admission(admissions[channel]),"host_channel_admission_rejected");
        const auto frames=callbacks[channel].admitted(admissions[channel]);
        check(frames.size()==2 && frames.front().wire_type==1,"host_channel_startup_failed");
    }
    registry.cancel_room(1,3);
    check(cleaned==std::array<int,3>{0,1,0},"host_cancel_crossed_channels");
    check(callbacks[2].message(admissions[2],{},Bytes{0,0}).size()==1,"host_surviving_channel_map_ready_failed");
    callbacks[0].disconnected(admissions[0]); registry.shutdown();
    check(cleaned==std::array<int,3>{1,1,1},"host_channel_cleanup_not_once");
}
}
int main(int argc,char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("usage: richonline_boss_host_tests <Richonline-resource-root>");
        const std::filesystem::path resources(argv[1]);
        optional_configuration_and_strict_policy(resources); real_resources_sqlite_revision_and_admission(resources);
        unsupported_room_and_strategy_mismatch_cleanly_fail(resources);
        real_host_uses_selected_channel_for_admission(resources);
        special_only_resources_use_selected_map(resources);
        std::cout << "PASS explicit BOSS host with SQLite, real resources and bound startup callbacks\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
