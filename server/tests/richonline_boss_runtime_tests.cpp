#include "richonline_boss_runtime.hpp"
#include "richonline_board.hpp"
#include "richonline_route.hpp"
#include "richonline_boss_stage.hpp"
#include "original_map.hpp"
#include "richonline_opening_hand.hpp"
#include "richonline_shop_catalog.hpp"
#include "original_options.hpp"
#include "../vendor/lzokay/lzokay.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void check(bool value,std::string_view reason) { if (!value) throw std::runtime_error(std::string(reason)); }
template<class Action> void rejects(Action action,std::string_view reason) {
    try { action(); } catch (const CodecError& error) { check(error.what() == reason,error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
void put(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) bytes.at(offset+i) = static_cast<std::uint8_t>(value >> (8*i));
}
Json configuration(const std::filesystem::path& resources) {
    const auto root = std::filesystem::absolute(resources).u8string();
    Json value{{"provenance","Isolated runtime test with real EMP resources; no complete gameplay claim."},
        {"game_capacity",8},{"player_capacity",100},{"stage_progress",{1,1,2,0}},{"setting_text","14"},{"room_unknown_prefix",9},
        {"richonline_boss_game",{{"version",1},{"provenance","Explicit isolated runtime configuration."},
            {"client_root",std::string(root.begin(),root.end())},{"advertised_ipv4",{127,0,0,1}},
            {"port",0},{"manager",0},{"admission_ttl_ms",30000},{"spawn_policy","resource-straight-road-farthest-v1"},
            {"token_policy","system-random-echo"},{"filler_policy","system-random-unconsumed"},
            {"wire",{{"provenance","f64 constructor baseline; explicit test session and unread wire bytes."},
                {"game_server_id",0x1234},{"calendar_counter",0x4567},{"year",2026},{"month",10},{"day",9},{"weekday",5},
                {"opaque_f64_hex","000000000000f03f"},{"opaque_header_byte",0xa1},{"opaque_trailing",{0xb1,0xc1}},
                {"synthetic_unconsumed_skill_bytes",{1,2,3,4,5,6,7,8,9,10}},{"envelope",{{"tag",7},{"mode",-2}}}}}}},
        {"richonline_boss_turn_policy",{{"provenance","Ordinary movement test policy; all actual landings rejected until implemented."},
            {"opaque_turn7",0xa2},{"inactive_ui_dice",{-7,9}},{"opaque20_23",{0xa3,0xb3,0xc3,0xd3}},
            {"optional_tail_hex","e1f2"},{"scope","ordinary-movement-unimplemented-landings-rejected"}}}};
    for (const auto& [name,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"unknown_channel_record_hex",80},{"unknown_role_record_hex",208},{"unknown_profile_record_hex",272},
        {"unknown_login_result_hex",16},{"unknown_identity_record_hex",16},{"unknown_empty_list_hex",4},{"unknown_bank_config_hex",32}})
        value[name] = std::string(size*2,'0');
    value["unknown_completion_hex"] = std::string(40,'0')+"000000000000f03f";
    return value;
}
struct Fixture {
    std::filesystem::path root = std::filesystem::absolute("boss-runtime-test-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::path file = root/"bootstrap.json";
    Storage storage;
    explicit Fixture(ClientProfile profile = ClientProfile::richonline) : storage(root/"accounts.sqlite3",profile) {}
    void save(const Json& config) { std::ofstream output(file); output << config; check(output.good(),"fixture_write_failed"); }
};
RichonlineRoomSnapshot room(const std::filesystem::path& resources,std::uint32_t actor) {
    RichonlineRoomSnapshot value{3,actor,{},{{77,actor,0,true}}};
    auto& e = value.description.extension; e = Bytes(88,0);
    constexpr std::string_view name = "BS_1_1.emp"; std::copy(name.begin(),name.end(),e.begin());
    const auto map = load_original_emp(resources/"Map"/name); std::copy(map.signature.begin(),map.signature.end(),e.begin()+32);
    put(e,48,3); put(e,52,1); put(e,56,10); put(e,60,3); put(e,64,100);
    value.description.record[32] = 0x40; value.description.record[36] = 3;
    value.description.record[40] = 1; value.description.record[120] = 88; value.description.record[124] = 1;
    return value;
}
void missing_config_and_original_profile(const std::filesystem::path& resources) {
    Fixture fixture;
    check(!load_richonline_boss_runtime(fixture.storage,fixture.file,{}),"absent_bootstrap_enabled");
    const auto complete = configuration(resources);
    auto missing = complete; missing.erase("richonline_boss_game"); missing.erase("richonline_boss_turn_policy"); fixture.save(missing);
    check(!load_richonline_boss_runtime(fixture.storage,fixture.file,{}),"absent_config_enabled");
    for (const auto key : {"richonline_boss_game","richonline_boss_turn_policy"}) {
        missing = complete; missing.erase(key); fixture.save(missing);
        rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_runtime_config_incomplete");
    }
    Fixture original(ClientProfile::original); original.save(complete);
    rejects([&] { load_richonline_boss_runtime(original.storage,original.file,{}); },"richonline_boss_runtime_client_profile_invalid");
}
void policy_requires_all_explicit_wire_fields(const std::filesystem::path& resources) {
    Fixture fixture; const auto complete = configuration(resources);
    for (const auto key : {"opaque_turn7","inactive_ui_dice","opaque20_23","optional_tail_hex","scope","provenance"}) {
        auto bad = complete; bad["richonline_boss_turn_policy"].erase(key); fixture.save(bad);
        rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_turn_policy_fields_invalid");
    }
    auto bad = complete; bad["richonline_boss_turn_policy"]["opaque_turn7"] = 256; fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_turn_policy_number_invalid");
    bad = complete; bad["richonline_boss_turn_policy"]["inactive_ui_dice"] = {-129,9}; fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_turn_policy_number_invalid");
    bad = complete; bad["richonline_boss_turn_policy"]["optional_tail_hex"] = "0g"; fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_turn_policy_tail_invalid");
    bad = complete; bad["richonline_boss_turn_policy"]["optional_tail_hex"] = std::string(522,'a'); fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_turn_policy_tail_invalid");
    bad = complete; bad["richonline_boss_turn_policy"]["scope"] = "complete-gameplay"; fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_turn_policy_scope_invalid");
    bad = complete;
    bad["richonline_boss_card_policy"]={{"provenance","Explicit experimental single-card event17 policy."},
        {"event_id",17},{"card_id",1038},{"opaque6_7",{0xa5,0x5a}}};
    bad["richonline_ground_card_policy"]={{"provenance","Explicit test ground-card range."},
        {"range_name","server_manhattan_tile_radius"},{"manhattan_radius",3}};
    fixture.save(bad);
    check(load_richonline_boss_runtime(fixture.storage,fixture.file,{}).has_value(),"card_policy_not_loaded");
    bad["richonline_boss_card_policy"]["card_id"]=1039; fixture.save(bad);
    check(load_richonline_boss_runtime(fixture.storage,fixture.file,{}).has_value(),"resource_card_policy_not_loaded");
    bad["richonline_boss_card_policy"].erase("opaque6_7"); fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_card_policy_fields_invalid");
    bad=complete; bad.erase("richonline_boss_game"); bad.erase("richonline_boss_turn_policy");
    bad["richonline_boss_card_policy"]={{"provenance","Orphan card policy must never be ignored."}}; fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_runtime_config_incomplete");
}
Bytes plain(const Frame& frame) { return decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded); }
void bank_policy_is_explicit_and_validated(const std::filesystem::path& resources) {
    Fixture fixture; auto config=configuration(resources);
    config["richonline_game_bank_policy"]={{"provenance","NEW consumed envelope with explicit unassigned padding policy."},
        {"admission_padding",0xa7},{"transaction_padding",{0xa6,0xb6}}};
    fixture.save(config);
    bool enabled=false;
    check(load_richonline_boss_runtime(fixture.storage,fixture.file,[&](const std::string& event,const Json& fields) {
        if (event=="richonline_boss_runtime_configured") enabled=fields.at("game_bank_supported").get<bool>();
    }).has_value() && enabled,"bank_policy_not_loaded");
    for (const auto* key:{"provenance","admission_padding","transaction_padding"}) {
        auto bad=config; bad["richonline_game_bank_policy"].erase(key); fixture.save(bad);
        rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_game_bank_policy_fields_invalid");
    }
    auto bad=config; bad["richonline_game_bank_policy"]["admission_padding"]=256; fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_turn_policy_number_invalid");
    bad=config; bad.erase("richonline_boss_game"); bad.erase("richonline_boss_turn_policy"); fixture.save(bad);
    rejects([&] { load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_boss_runtime_config_incomplete");
}
void npc_policy_reaches_real_startup(const std::filesystem::path& resources) {
    Fixture fixture; auto config=configuration(resources);
    config["richonline_npc_policy"]={{"provenance","Explicit experimental unread ground object byte policy."},
        {"god_bytes",{0xa7,0xa8}},{"chest_bytes",{0xc7,0xc8}}};
    fixture.save(config);
    rejects([&]{ load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_npc_cards_required");
    config["richonline_boss_card_policy"]={{"provenance","Explicit test enabled resource card policy."},
        {"event_id",17},{"card_id",1038},{"opaque6_7",{0xa5,0x5a}}};
    config["richonline_ground_card_policy"]={{"provenance","Explicit NPC startup test ground-card range."},
        {"range_name","server_manhattan_tile_radius"},{"manhattan_radius",3}};
    for (const auto key:{"provenance","god_bytes","chest_bytes"}) {
        auto invalid=config; invalid["richonline_npc_policy"].erase(key); fixture.save(invalid);
        rejects([&]{ load_richonline_boss_runtime(fixture.storage,fixture.file,{}); },"richonline_npc_policy_fields_invalid");
    }
    fixture.save(config);
    const auto actor=fixture.storage.dispatch("accounts.create",{{"username","npc-runtime"},{"password","fixture"}})
        .at("account").at("role_id").get<std::uint32_t>();
    bool enabled=false;
    auto runtime=load_richonline_boss_runtime(fixture.storage,fixture.file,[&](const std::string& event,const Json& fields){
        if (event=="richonline_boss_runtime_configured") enabled=fields.at("closed_npc_flow_supported").get<bool>();
    });
    check(runtime && enabled,"npc_runtime_policy_not_enabled");
    auto plans=runtime->provider(19001,room(resources,actor));
    check(plans.size()==1,"npc_runtime_plan_missing");
    auto& plan=plans.front(); plan.admitted();
    const auto opening=plan.message({},Bytes{0,0});
    check(opening.size()==11,"npc_opening_missing_spawn_or_turn");
    const auto human_hand=decode_richonline_inventory_prefix4019(plain(opening[1]),2);
    const auto boss_hand=decode_richonline_inventory_prefix4019(plain(opening[2]),2);
    check(human_hand.actor==0 && human_hand.slots[0]==RichonlineChanceCardSlot{1038,1} &&
        human_hand.slots[1]==RichonlineChanceCardSlot{1044,1} && boss_hand.actor==1 &&
        std::all_of(boss_hand.slots.begin(),boss_hand.slots.end(),[](const auto& slot){return slot.card_id==-1 && slot.count==0;}),
        "opening_hand_not_synchronized_before_turn");
    check(plan.message({},Bytes{0,0}).empty(),"duplicate_map_ready_reset_hand");
    std::vector<std::uint32_t> kinds,positions;
    const auto topology=load_richonline_road_topology(resources/"Map/BS_1_1.emp");
    for (const auto& frame:opening) {
        const auto bytes=plain(frame);
        if (read_le(View(bytes).first(2))!=0x401c) continue;
        const bool chest=bytes[6]==9;
        check(bytes.size()==9 && bytes[7]==(chest ? 0xc7 : 0xa7) && bytes[8]==(chest ? 0xc8 : 0xa8),
            "npc_wire_policy_not_preserved");
        const auto position=read_le(View(bytes).subspan(4,2));
        check(topology.cell(static_cast<std::int16_t>(position)).walkable,"npc_spawn_not_walkable");
        check(std::find(positions.begin(),positions.end(),position)==positions.end(),"npc_spawns_overlap");
        positions.push_back(position); kinds.push_back(bytes[6]);
    }
    std::sort(kinds.begin(),kinds.end());
    check(kinds==std::vector<std::uint32_t>{0,1,2,3,9},"npc_closed_map_pool_not_applied");
    plan.disconnected();
}
void actual_startup_freezes_policy_and_resolves_supported_landings(const std::filesystem::path& resources) {
    Fixture fixture; auto config = configuration(resources);
    const auto relative = std::filesystem::relative(std::filesystem::absolute(resources),fixture.root).u8string();
    config["richonline_boss_game"]["client_root"] = std::string(relative.begin(),relative.end()); fixture.save(config);
    const auto actor = fixture.storage.dispatch("accounts.create",{{"username","runtime-fixture"},{"password","local-only"}})
        .at("account").at("role_id").get<std::uint32_t>();
    std::vector<Json> logs;
    auto runtime = load_richonline_boss_runtime(fixture.storage,fixture.file,[&](const std::string& event,const Json& fields) {
        logs.push_back({{"event",event},{"fields",fields}});
    });
    check(runtime.has_value(),"runtime_not_loaded");
    config["richonline_boss_turn_policy"]["opaque_turn7"] = 0x77;
    config["richonline_boss_game"]["client_root"] = "intentionally-absent"; fixture.save(config);
    const auto map = load_richonline_road_topology(resources/"Map/BS_1_1.emp");
    for (int session = 0; session < 3; ++session) {
        auto plans = runtime->provider(19001,room(resources,actor)); check(plans.size() == 1,"plan_missing");
        auto& plan = plans.front(); const auto initial = plan.admitted();
        check(initial.size() == 2 && initial[0].wire_type == 1 && initial[0].payload.empty(),"admission_ack_must_precede_init");
        check(plain(initial[1]).size() == 52,"actual_init_missing");
        check(plan.message({},Bytes{1,0}).empty(),"init_notification_starts_turn");
        const auto opening = plan.message({},Bytes{0,0});
        check(opening.size() == 4 && read_le(View(plain(opening[0])).first(2)) == 0x4004 &&
            plain(opening[1]) == Bytes({0x10,0x40,0x34,0x12,1,1,0,0xa2}) &&
            plain(opening[2]) == Bytes({0x0f,0x42,0x34,0x12,0xff,0xff}),"opening_or_frozen_policy_wrong");
        const auto move = plain(opening[3]);
        check(move.size() == 30 && read_le(View(move).first(2)) == 0x4011 && read_le(View(move).subspan(4,2)) == 236 &&
            move[6] == 1 && move[8] >= 1 && move[8] <= 6 && move[7] == move[8] && move[9] == 0xf9 && move[10] == 9 &&
            read_le(View(move).subspan(20,4)) == 0xd3c3b3a3U && read_le(View(move).subspan(24,4)) == 0 &&
            move[28] == 0xe1 && move[29] == 0xf2,"bounded_roll_or_wire_policy_wrong");
        std::int16_t endpoint = 236;
        for (std::size_t i = 0; i < move[7]; ++i) {
            const auto direction = static_cast<std::size_t>((move[11+i/4] >> (2*(i%4)))&3U);
            const auto next = map.cell(endpoint).neighbors[direction]; check(next.has_value(),"random_route_not_adjacent"); endpoint = *next;
        }
        Bytes stop; append_le(stop,0x11,2); append_le(stop,0x4568,2); append_le(stop,static_cast<std::uint16_t>(endpoint),2);
        if (endpoint >= 230 && endpoint <= 235) {
            const auto next = plan.message({},stop);
            const std::size_t turn_index = endpoint >= 231 && endpoint <= 233 ? 2U : 1U;
            check(next.size() == turn_index+2 && plain(next[0]) == Bytes({0x13,0x40,0x34,0x12,static_cast<std::uint8_t>(endpoint),0}) &&
                plain(next[turn_index]) == Bytes({0x10,0x40,0x34,0x12,0,1,0,0xa2}) &&
                plain(next[turn_index+1]) == Bytes({0x0f,0x42,0x34,0x12,0xff,0xff}),"proven_boss_landing_did_not_reach_human_turn");
            if (endpoint == 233) check(plain(next[1]) == Bytes({0x31,0x40,0x34,0x12,0xff}),"boss_shop_wait_not_closed");
            if (endpoint == 231 || endpoint == 232)
                check(plain(next[1]) == Bytes({0x20,0x40,0x34,0x12,1}),"boss_affordable_property_not_purchased");
        } else {
            rejects([&] { plan.message({},stop); },"richonline_boss_landing_unsupported");
            const auto& last = logs.back();
            check(last.at("event") == "richonline_boss_landing_rejected" && last.at("fields").at("actor_slot") == 1 &&
                last.at("fields").at("position") == endpoint && last.at("fields").at("static_type") == map.cell(endpoint).static_type &&
                last.at("fields").at("property_ref") == map.cell(endpoint).property_ref &&
                last.at("fields").at("runtime_client_verified") == false,"landing_diagnostic_not_precise");
        }
        plan.disconnected();
    }
    check(std::any_of(logs.begin(),logs.end(),[](const Json& item) {
        return item.at("event") == "richonline_boss_runtime_configured" && item.at("fields").at("game_ready") == false &&
            item.at("fields").at("scope") == "ordinary-movement-unimplemented-landings-rejected";
    }),"runtime_scope_not_reported");
}
void runtime_selects_special_map_package_without_ordinary_fallback(const std::filesystem::path& resources) {
    Fixture fixture; fixture.save(configuration(resources));
    const auto actor=fixture.storage.dispatch("accounts.create",{{"username","map-package-fixture"},{"password","local-only"}})
        .at("account").at("role_id").get<std::uint32_t>();
    std::vector<Json> logs;
    auto runtime=load_richonline_boss_runtime(fixture.storage,fixture.file,[&](const std::string& event,const Json& fields) {
        logs.push_back({{"event",event},{"fields",fields}});
    });
    auto special=room(resources,actor);
    const auto stage=load_richonline_boss_stage(resources,"V_BS_1_1.emp",2);
    auto& extension=special.description.extension;
    std::fill(extension.begin(),extension.begin()+32,0);
    std::copy(stage.map_name.begin(),stage.map_name.end(),extension.begin());
    std::copy(stage.signature.begin(),stage.signature.end(),extension.begin()+32);
    put(extension,56,stage.wait_seconds); put(extension,60,stage.game_months);
    put(extension,64,stage.pawn_gold); put(extension,68,2);
    rejects([&] { runtime->provider(19001,special); },"richonline_map_package_runtime_incomplete");
    check(std::any_of(logs.begin(),logs.end(),[](const Json& entry) {
        return entry.at("event")=="richonline_map_package_pending" &&
            entry.at("fields").at("package")=="zhao_linger" && entry.at("fields").at("category")==2;
    }),"special_map_did_not_reach_its_own_package");
    auto ordinary=runtime->provider(19001,room(resources,actor));
    check(ordinary.size()==1,"special_rejection_poisoned_next_ordinary_session");
    check(static_cast<bool>(ordinary.front().sent),"runtime_raw_whole_frame_observer_missing");
    ordinary.front().admitted();
    const auto ready=ordinary.front().message({},Bytes{0,0});
    for (const auto& frame:ready) ordinary.front().sent(frame);
    ordinary.front().disconnected();
}
Json terminal_configuration() {
    return {{"provenance","Explicit emulator rules: resource win rewards, returned winning pledge, no loss/draw award."},
        {"client_sha256","cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77"},
        {"simultaneous_defeat","human_loss"},{"win_rank",1},{"loss_rank",2},{"draw_rank",2},
        {"show_text_270",false},{"result_display_ms",6000},{"map_load_timeout_ms",90000},{"return_winning_pledge",true},
        {"first_win_bonus",0},{"repeat_win_bonus",0},
        {"loss",{{"experience",0},{"gold_return",0},{"bonus_gold",0}}},
        {"draw",{{"experience",0},{"gold_return",0},{"bonus_gold",0}}}};
}
void terminal_runtime_reserves_after_validation_and_cleans_once(const std::filesystem::path& resources) {
    Fixture fixture; auto config=configuration(resources);
    config["richonline_terminal_policy"]=terminal_configuration();
    for (const auto key:{"client_sha256","result_display_ms","loss","draw","provenance"}) {
        auto invalid=config;invalid["richonline_terminal_policy"].erase(key);fixture.save(invalid);
        rejects([&]{load_richonline_boss_runtime(fixture.storage,fixture.file,{});},"richonline_terminal_policy_fields_invalid");
    }
    auto invalid=config;invalid["richonline_terminal_policy"]["win_rank"]=2;fixture.save(invalid);
    rejects([&]{load_richonline_boss_runtime(fixture.storage,fixture.file,{});},"richonline_terminal_policy_rank_invalid");
    invalid=config;invalid["richonline_terminal_policy"]["client_sha256"]="another-client";fixture.save(invalid);
    rejects([&]{load_richonline_boss_runtime(fixture.storage,fixture.file,{});},"richonline_result_byte18_compatibility_scope_mismatch");
    fixture.save(config);
    const auto actor=fixture.storage.dispatch("accounts.create",{{"username","terminal-runtime"},{"password","fixture"}})
        .at("account").at("role_id").get<std::uint32_t>();
    const auto before=fixture.storage.game_account_for_role(actor).gold;
    check(before>=100,"terminal_fixture_entry_funds_missing");
    auto runtime=load_richonline_boss_runtime(fixture.storage,fixture.file,{});
    auto rejected=room(resources,actor);put(rejected.description.extension,56,11);
    rejects([&]{runtime->provider(19001,rejected);},"richonline_boss_room_resource_mismatch");
    check(fixture.storage.game_account_for_role(actor).gold==before,"invalid_startup_debited_entry");
    auto prestart=runtime->provider(19001,room(resources,actor));
    check(fixture.storage.game_account_for_role(actor).gold==before-100,"entry_pledge_not_reserved");
    prestart.front().disconnected();prestart.front().disconnected();
    check(fixture.storage.game_account_for_role(actor).gold==before,"startup_cleanup_not_refunded_once");
    auto playing=runtime->provider(19001,room(resources,actor));playing.front().admitted();
    check(!playing.front().message({},Bytes{0,0}).empty(),"terminal_playing_start_missing");
    playing.front().disconnected();playing.front().disconnected();
    check(fixture.storage.game_account_for_role(actor).gold==before-100,"playing_abandon_refunded_or_double_charged");
    const auto remaining=fixture.storage.game_account_for_role(actor).gold;
    check(remaining>99,"insufficient_funds_fixture_balance_low");
    const auto drained=fixture.storage.consume_game_gold("terminal-runtime",actor,
        {remaining-99,"terminal-fixture-lower-funds","fixture insufficient entry balance"});
    check(drained.status==GameChargeStatus::success,"fixture_account_charge_failed");
    rejects([&]{runtime->provider(19001,room(resources,actor));},"game_pledge_insufficient_funds");
    check(fixture.storage.game_account_for_role(actor).gold==99,"refused_entry_changed_balance");
}
void combat_runtime_supplies_timed_bomb_authority(const std::filesystem::path& resources) {
    Fixture fixture;auto config=configuration(resources);
    config["richonline_terminal_policy"]=terminal_configuration();
    config["richonline_boss_card_policy"]={{"provenance","Explicit runtime timed-bomb authority test."},
        {"event_id",17},{"card_id",1038},{"opaque6_7",{0xa5,0x5a}}};
    config["richonline_combat_policy"]={{"provenance","Explicit closed mode3 combat runtime authority test."},
        {"range_name","server_manhattan_tile_radius"},{"manhattan_radius",3},
        {"projectile_candidates","road_tiles"},{"mine_landing_policy","closed-static-road-v1"},
        {"neutral_human_equipment",Json::array()}};
    fixture.save(config);
    const auto actor=fixture.storage.dispatch("accounts.create",{{"username","bomb-runtime"},{"password","fixture"}})
        .at("account").at("role_id").get<std::uint32_t>();
    bool enabled=false;
    auto runtime=load_richonline_boss_runtime(fixture.storage,fixture.file,[&](const std::string& event,const Json& fields) {
        if(event=="richonline_boss_runtime_configured") {
            enabled=fields.at("timed_bomb_session_supported").get<bool>();
            check(fields.at("timed_bomb_raw_policy")=="closed_initial_status_policy" &&
                fields.at("timed_bomb_unconsumed_byte_policy")=="system-random-unconsumed",
                "timed_bomb_runtime_policy_not_named");
        }
    });
    check(runtime && enabled,"timed_bomb_runtime_not_enabled_with_combat");
    auto plans=runtime->provider(19001,room(resources,actor));auto& plan=plans.at(0);
    const auto admitted=plan.admitted();for(const auto& frame:admitted) plan.sent(frame);
    const auto opening=plan.message({},Bytes{0,0});
    std::optional<Bytes> move;
    for(const auto& frame:opening) {
        plan.sent(frame);const auto bytes=plain(frame);
        if(read_le(View(bytes).first(2))==0x4011) move=bytes;
    }
    check(move.has_value(),"timed_bomb_runtime_opening_move_missing");
    const auto topology=load_richonline_road_topology(resources/"Map/BS_1_1.emp");
    auto endpoint=static_cast<std::int16_t>(read_le(View(*move).subspan(4,2)));
    for(std::size_t step=0;step<(*move)[7];++step) {
        const auto direction=static_cast<std::size_t>(((*move)[11+step/4]>>(2*(step%4)))&3U);
        endpoint=topology.cell(endpoint).neighbors[direction].value();
    }
    Bytes stop;append_le(stop,0x11,2);append_le(stop,0x4568,2);append_le(stop,static_cast<std::uint16_t>(endpoint),2);
    const auto human=plan.message({},stop);
    bool human_turn=false;
    for(const auto& frame:human) {
        plan.sent(frame);const auto bytes=plain(frame);
        if(read_le(View(bytes).first(2))==0x4010 && bytes[4]==0) human_turn=true;
    }
    check(human_turn,"timed_bomb_runtime_did_not_continue_to_human");
    // The opening hand has controlled dice and a mine, so this must reach
    // precise inventory validation after the real raw-state projection.
    rejects([&] { plan.message({},Bytes{110,0,0x69,0x45,0,0,1,0xcc}); },
        "richonline_timed_bomb_card_not_owned");
    plan.disconnected();
}
void cards_without_combat_can_buy_and_place_banana(const std::filesystem::path& resources) {
    Fixture fixture;
    const auto isolated=fixture.root/"resources";
    std::filesystem::create_directories(isolated);
    for(const auto name:{"Data","Map"})
        std::filesystem::copy(resources/name,isolated/name,std::filesystem::copy_options::recursive);
    const auto source_catalog=RichonlineShopCatalog::load(resources,"BS_1_1.emp");
    std::vector<std::int16_t> retained{507};
    for(const auto& offer:source_catalog.offers())
        if(offer.card_id!=507 && retained.size()<12) retained.push_back(offer.card_id);
    check(retained.size()==12,"shop_fixture_requires_twelve_real_offers");
    const auto decoded=load_original_kpd(resources/"Data/Prop.kpd");
    std::string props(decoded.begin(),decoded.end());
    // Preserve every real resource field except sale eligibility. Exactly twelve
    // real offers make banana placement deterministic despite shuffled stock.
    for(std::size_t offset=0;(offset=props.find("saleG",offset))!=std::string::npos;) {
        const auto section=props.rfind("[PROP]",offset);
        const auto index=props.find("indx",section);
        check(section!=std::string::npos && index!=std::string::npos && index<offset,
            "shop_fixture_prop_layout_changed");
        const auto id=std::stoi(props.substr(props.find('=',index)+1));
        const auto value=props.find_first_not_of(" \t",props.find('=',offset)+1);
        if(props.compare(value,4,"true")==0 && std::find(retained.begin(),retained.end(),id)==retained.end()) {
            props.replace(value,4,"false");offset=value+5;
        } else offset=value+4;
    }
    Bytes compressed(lzokay::compress_worst_size(props.size()));std::size_t compressed_size=0;
    check(lzokay::compress(reinterpret_cast<const std::uint8_t*>(props.data()),props.size(),
        compressed.data(),compressed.size(),compressed_size)==lzokay::EResult::Success,"shop_fixture_compression_failed");
    Bytes packed{42};append_le(packed,static_cast<std::uint32_t>(props.size()),4);
    append_le(packed,static_cast<std::uint32_t>(compressed_size),4);
    packed.insert(packed.end(),compressed.begin(),compressed.begin()+static_cast<std::ptrdiff_t>(compressed_size));
    for(std::size_t i=1;i<packed.size();++i) packed[i]=static_cast<std::uint8_t>(packed[i]+42);
    {
        std::ofstream output(isolated/"Data/Prop.kpd",std::ios::binary|std::ios::trunc);
        output.write(reinterpret_cast<const char*>(packed.data()),static_cast<std::streamsize>(packed.size()));
        check(output.good(),"shop_fixture_resource_write_failed");
    }
    check(RichonlineShopCatalog::load(isolated,"BS_1_1.emp").offers().size()==12,
        "shop_fixture_sale_filter_failed");
    auto config=configuration(isolated);
    config["richonline_boss_card_policy"]={{"provenance","Explicit cards-only runtime integration test."},
        {"event_id",17},{"card_id",1038},{"opaque6_7",{0xa5,0x5a}}};
    fixture.save(config);
    rejects([&]{load_richonline_boss_runtime(fixture.storage,fixture.file,{});},
        "richonline_ground_card_policy_required");
    config["richonline_ground_card_policy"]={{"provenance","Test operator authorizes roads within three Manhattan tiles."},
        {"range_name","server_manhattan_tile_radius"},{"manhattan_radius",3}};
    for(const auto key:{"provenance","range_name","manhattan_radius"}) {
        auto invalid=config;invalid["richonline_ground_card_policy"].erase(key);fixture.save(invalid);
        rejects([&]{load_richonline_boss_runtime(fixture.storage,fixture.file,{});},
            "richonline_ground_card_policy_fields_invalid");
    }
    fixture.save(config);
    const auto actor=fixture.storage.dispatch("accounts.create",{{"username","ground-runtime"},{"password","fixture"}})
        .at("account").at("role_id").get<std::uint32_t>();
    bool configured=false;
    auto runtime=load_richonline_boss_runtime(fixture.storage,fixture.file,[&](const std::string& event,const Json& fields) {
        if(event=="richonline_boss_runtime_configured") configured=fields.at("ground_card_range_configured").get<bool>() &&
            !fields.at("combat_session_supported").get<bool>() && !fields.at("timed_bomb_session_supported").get<bool>();
    });
    check(configured,"cards_only_ground_policy_not_configured");
    auto plans=runtime->provider(19001,room(resources,actor));auto& plan=plans.at(0);
    for(const auto& frame:plan.admitted()) plan.sent(frame);
    const auto topology=load_richonline_road_topology(resources/"Map/BS_1_1.emp");
    std::optional<Bytes> move;
    std::uint16_t calendar=0x4567;
    auto send=[&](const Bytes& wire) {
        std::vector<Bytes> result;
        for(const auto& frame:plan.message({},wire)) {
            plan.sent(frame);auto bytes=plain(frame);
            const auto opcode=read_le(View(bytes).first(2));
            if(opcode==0x4010) ++calendar;
            if(opcode==0x4011) move=bytes;
            result.push_back(std::move(bytes));
        }
        return result;
    };
    auto stop=[&] {
        check(move.has_value(),"cards_only_runtime_route_missing");
        auto endpoint=static_cast<std::int16_t>(read_le(View(*move).subspan(4,2)));
        for(std::size_t step=0;step<(*move)[7];++step) {
            const auto direction=static_cast<std::size_t>(((*move)[11+step/4]>>(2*(step%4)))&3U);
            endpoint=topology.cell(endpoint).neighbors[direction].value();
        }
        move.reset();Bytes wire;append_le(wire,0x11,2);append_le(wire,calendar,2);
        append_le(wire,static_cast<std::uint16_t>(endpoint),2);
        return send(wire);
    };
    auto action=[&](std::uint16_t opcode,std::uint8_t value) {
        Bytes wire;append_le(wire,opcode,2);append_le(wire,calendar,2);wire.push_back(value);wire.push_back(0xcc);
        return send(wire);
    };
    send({0,0});stop();
    // The real resource route115->114->130->146->162->178 enters a shop.
    Bytes dice{103,0,static_cast<std::uint8_t>(calendar),static_cast<std::uint8_t>(calendar>>8),
        0,0,5,0xcc,0,0,0,0};
    send(dice);const auto shop=stop();
    const auto stock=std::find_if(shop.begin(),shop.end(),[](const Bytes& b){return read_le(View(b).first(2))==0x4030;});
    check(stock!=shop.end(),"cards_only_runtime_shop_not_opened");
    std::optional<std::uint8_t> offer;
    for(std::uint8_t slot=0;slot<12;++slot)
        if(read_le(View(*stock).subspan(4+6U*slot,2))==507) offer=slot;
    check(offer.has_value(),"real_shop_banana_offer_missing");
    const auto bought=action(0x30,*offer);
    check(bought==std::vector<Bytes>{{0x31,0x40,0x34,0x12,*offer}},"cards_only_runtime_banana_buy_failed");
    action(0x30,255);action(0x34,0);stop();
    // Consumed opening die frees slot0; shop insertion places banana there.
    const auto target=std::int16_t{162};
    Bytes banana{165,0,static_cast<std::uint8_t>(calendar),static_cast<std::uint8_t>(calendar>>8),0,0,
        static_cast<std::uint8_t>(target),0};
    check(send(banana)==std::vector<Bytes>{{0xf5,0x40,0x34,0x12,0,0,162,0}},
        "cards_only_runtime_banana_response_wrong");
    plan.disconnected();
}
}
int main(int argc,char** argv) {
    try {
        check(argc == 2,"resource_path_required"); const std::filesystem::path resources(argv[1]);
        missing_config_and_original_profile(resources); policy_requires_all_explicit_wire_fields(resources);
        bank_policy_is_explicit_and_validated(resources);
        npc_policy_reaches_real_startup(resources);
        actual_startup_freezes_policy_and_resolves_supported_landings(resources);
        runtime_selects_special_map_package_without_ordinary_fallback(resources);
        terminal_runtime_reserves_after_validation_and_cleans_once(resources);
        combat_runtime_supplies_timed_bomb_authority(resources);
        cards_without_combat_can_buy_and_place_banana(resources);
        std::cout << "PASS real-resource startup with crypto dice and proven empty BOSS landings; other landings rejected\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
