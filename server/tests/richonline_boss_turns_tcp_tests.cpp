#include "richonline_boss_host.hpp"
#include "richonline_boss_turns.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_boss_cards.hpp"
#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "original_map.hpp"
#include "service.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
using Json = nlohmann::json;
constexpr std::uint16_t server_id = 0x1234, initial_counter = 0x4567;
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
struct Network {
    Network() { WSADATA data{}; check(WSAStartup(MAKEWORD(2,2),&data) == 0,"winsock_start_failed"); }
    ~Network() { WSACleanup(); }
};
struct Peer {
    SOCKET socket = INVALID_SOCKET;
    explicit Peer(std::uint16_t port) {
        socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        check(socket != INVALID_SOCKET,"socket_failed");
        try {
            const DWORD timeout = 3000;
            for (const auto option : {SO_RCVTIMEO,SO_SNDTIMEO})
                check(setsockopt(socket,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) == 0,"timeout_setup_failed");
            sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
            check(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr) == 1,"address_invalid");
            check(::connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address)) == 0,"connect_failed");
        } catch (...) { close(); throw; }
    }
    ~Peer() { close(); }
    Peer(const Peer&) = delete;
    Peer& operator=(const Peer&) = delete;
    void close() { if (socket != INVALID_SOCKET) { closesocket(socket); socket = INVALID_SOCKET; } }
    void send_frame(const Frame& frame) {
        const auto encoded = encode_frame(frame,{Channel::game_c2s,{},ClientVersion::richonline});
        View remaining(encoded);
        while (!remaining.empty()) {
            const auto count = ::send(socket,reinterpret_cast<const char*>(remaining.data()),static_cast<int>(remaining.size()),0);
            check(count > 0,"send_failed"); remaining = remaining.subspan(static_cast<std::size_t>(count));
        }
    }
    void send(View plain) { send_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91))); }
    Bytes read(std::size_t length) {
        Bytes result(length);
        for (std::size_t offset = 0; offset < length;) {
            const auto count = recv(socket,reinterpret_cast<char*>(result.data()+offset),static_cast<int>(length-offset),0);
            check(count > 0,"receive_failed"); offset += static_cast<std::size_t>(count);
        }
        return result;
    }
    Frame receive_frame() {
        auto bytes = read(8); const auto total = read_le(View(bytes).subspan(4,4));
        check(total >= 8 && total <= max_frame_total,"frame_length_invalid");
        const auto payload = read(total-8); bytes.insert(bytes.end(),payload.begin(),payload.end());
        return decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
    }
    Bytes receive() {
        const auto frame = receive_frame();
        check(frame.wire_type == 299,"expected_game_envelope");
        const auto envelope = decode_envelope(frame,ClientVersion::richonline);
        check(envelope.inner_type == 7 && envelope.mode == -2,"envelope_policy_lost");
        return decode_inner(envelope.encoded);
    }
};
void put(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) bytes.at(offset+i) = static_cast<std::uint8_t>(value >> (8*i));
}
Bytes request(std::uint16_t opcode,std::uint16_t counter,std::uint32_t argument,std::size_t width = 2) {
    Bytes result; append_le(result,opcode,2); append_le(result,counter,2); append_le(result,argument,width); return result;
}
Json configuration(const std::filesystem::path& resources) {
    const auto path = std::filesystem::absolute(resources).u8string();
    Json value{{"provenance","Isolated TCP bootstrap for scoped real landing and lifecycle fixture tests; not complete gameplay."},
        {"game_capacity",8},{"player_capacity",100},{"stage_progress",{1,1,2,0}},{"setting_text","14"},{"room_unknown_prefix",9},
        {"richonline_boss_game",{{"version",1},{"provenance","Explicit isolated TCP engine test policy."},
            {"client_root",std::string(path.begin(),path.end())},{"advertised_ipv4",{127,0,0,1}},
            {"port",0},{"manager",0},{"admission_ttl_ms",30000},{"spawn_policy","resource-straight-road-farthest-v1"},
            {"token_policy","system-random-echo"},{"filler_policy","system-random-unconsumed"},
            {"wire",{{"provenance","Constructor f64 and explicit test date/counter/opaque wire policy."},
                {"game_server_id",server_id},{"calendar_counter",initial_counter},{"year",2026},{"month",10},{"day",9},{"weekday",5},
                {"opaque_f64_hex","000000000000f03f"},{"opaque_header_byte",0xa1},{"opaque_trailing",{0xb1,0xc1}},
                {"synthetic_unconsumed_skill_bytes",{1,2,3,4,5,6,7,8,9,10}},{"envelope",{{"tag",7},{"mode",-2}}}}}}}};
    for (const auto& [name,size] : std::initializer_list<std::pair<const char*,std::size_t>>{
        {"unknown_channel_record_hex",80},{"unknown_role_record_hex",208},{"unknown_profile_record_hex",272},
        {"unknown_login_result_hex",16},{"unknown_identity_record_hex",16},{"unknown_empty_list_hex",4},{"unknown_bank_config_hex",32}})
        value[name] = std::string(size*2,'0');
    value["unknown_completion_hex"] = std::string(40,'0')+"000000000000f03f";
    return value;
}
RichonlineRoomSnapshot resource_room(const std::filesystem::path& resources,std::uint32_t actor) {
    RichonlineRoomSnapshot room{3,actor,{},{{77,actor,0,true}}};
    auto& e = room.description.extension; e = Bytes(88,0);
    constexpr std::string_view name = "BS_1_1.emp"; std::copy(name.begin(),name.end(),e.begin());
    const auto map = load_original_emp(resources/"Map"/name); std::copy(map.signature.begin(),map.signature.end(),e.begin()+32);
    put(e,48,3); put(e,52,1); put(e,56,10); put(e,60,3); put(e,64,100);
    room.description.record[32] = 0x40; room.description.record[36] = 3;
    room.description.record[40] = 1; room.description.record[120] = 88; room.description.record[124] = 1;
    return room;
}
struct Observations {
    std::mutex mutex;
    std::condition_variable changed;
    bool listening = false;
    std::exception_ptr failure;
    std::vector<std::string> logs;
    std::vector<RichonlineLandingContext> landings;
    unsigned events = 0, cleanup = 0;
    template<class Predicate> void wait(Predicate predicate) {
        std::unique_lock lock(mutex);
        check(changed.wait_for(lock,std::chrono::seconds(5),[&] { return failure || predicate(); }),"service_event_timeout");
        if (failure) std::rethrow_exception(failure);
    }
    void log(const std::string& line) {
        const std::lock_guard lock(mutex); logs.push_back(line);
        if (line.starts_with("game_transport_listening port=")) listening = true;
        changed.notify_all();
    }
};
struct Scenario {
    std::filesystem::path root = std::filesystem::absolute("boss-turns-tcp-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Storage storage{root/"accounts.sqlite3"};
    std::uint32_t actor = storage.dispatch("accounts.create",{{"username","tcp-fixture"},{"password","local-test-only"}})
        .at("account").at("role_id").get<std::uint32_t>();
    RichonlineRoomSnapshot room;
    Observations observed;
    std::optional<RichonlineRuntimeGame> host;
    std::unique_ptr<RichonlineGameRegistry> registry;
    std::unique_ptr<GameService> service;
    std::optional<GameAdmission> direct_admission;
    std::thread worker;
    Scenario(const std::filesystem::path& resources,bool wait_event,bool actual_landing = false,std::uint8_t steps = 1,
        std::shared_ptr<RichonlineBossCards> cards = {},std::shared_ptr<RichonlineBossProperty> property = {})
        : room(resource_room(resources,actor)) {
        const auto file = root/"bootstrap.json";
        { std::ofstream output(file); output << configuration(resources); check(output.good(),"fixture_write_failed"); }
        const auto topology = load_richonline_road_topology(resources/"Map/BS_1_1.emp");
        auto strategy = [&,topology,wait_event,actual_landing,steps,cards,property](const RichonlineBossStartup& startup) {
            RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
                [steps](std::size_t bound) {
                    check(bound > 0 && steps >= 1 && steps <= 6,"invalid_fixture_random_domain");
                    return bound == 6 ? static_cast<std::size_t>(steps-1) : std::size_t{0};
                },
                [&,wait_event,actual_landing,property](const RichonlineLandingContext& landing) {
                    { const std::lock_guard lock(observed.mutex); observed.landings.push_back(landing); observed.changed.notify_all(); }
                    if (property) if (auto result = property->land(landing)) return std::move(*result);
                    if (actual_landing) return resolve_richonline_empty_boss_landing(server_id,landing);
                    return RichonlineLandingResult{{},wait_event ? RichonlineLandingProgress::await_event : RichonlineLandingProgress::complete};
                },[&,actual_landing](View plain) {
                    check(!actual_landing,"actual_landing_reached_fixture_event");
                    check(plain.size() == 6 && read_le(plain.first(2)) == 0x55,"fixture_event_invalid");
                    const std::lock_guard lock(observed.mutex); ++observed.events; observed.changed.notify_all();
                    return RichonlineLandingResult{{},RichonlineLandingProgress::complete};
                }};
            rules.cards = cards;
            rules.log = [this](const std::string& line) { observed.log(line); };
            auto selected = startup;
            if (property) {
                selected.init.participants[0].position = 233;
                selected.init.participants[0].direction = 1;
                rules.event = [this,property](View plain) {
                    { const std::lock_guard lock(observed.mutex); ++observed.events; observed.changed.notify_all(); }
                    return property->decide(plain);
                };
                rules.poll = [property] { return property->poll(); };
            }
            auto plan = make_richonline_boss_turns(selected,topology,std::move(rules));
            plan.disconnected = [this,close = std::move(plan.disconnected)] {
                close(); const std::lock_guard lock(observed.mutex); ++observed.cleanup; observed.changed.notify_all();
            };
            return plan;
        };
        host = load_richonline_boss_host(storage,file,{},strategy);
        check(host.has_value(),"host_not_configured");
        registry = std::make_unique<RichonlineGameRegistry>([this](const RichonlineRoomSnapshot& value) {
            return host->provider(service->bound_port(),value);
        },host->manager,host->admission_ttl);
        if (property) direct_admission = GameAdmission{0,room.key,actor,{1,2,3,4,5,6,7,8},0x8b7a6910,{}};
        service = std::make_unique<GameService>(ServiceOptions{"127.0.0.1",0,ClientVersion::richonline},
            [this,resources,strategy] {
                if (!direct_admission) return registry->callbacks();
                return make_richonline_game_callbacks([this,resources,strategy](const GameAdmission& admission)
                    -> std::optional<RichonlineStartupPlan> {
                    if (admission != *direct_admission) return {};
                    const RichonlineBossWirePolicy wire{server_id,initial_counter,2026,10,9,5,
                        {0,0,0,0,0,0,0xf0,0x3f},0xa1,{0xb1,0xc1},{1,2,3,4,5,6,7,8,9,10},{7,-2}};
                    return strategy(build_richonline_boss_startup(resources,room,
                        {static_cast<std::int16_t>(actor),{},{7,7,7,7,7,7,7,7,7,7},wire}));
                },[](std::size_t size) { return Bytes(size,0x91); });
            },[this](const std::string& line) { observed.log(line); });
        worker = std::thread([this] {
            try { service->run(); } catch (...) {
                const std::lock_guard lock(observed.mutex); observed.failure = std::current_exception(); observed.changed.notify_all();
            }
        });
        try { observed.wait([&] { return observed.listening; }); }
        catch (...) { service->stop(); worker.join(); throw; }
    }
    ~Scenario() { stop(); }
    void stop() {
        if (service) service->stop();
        if (worker.joinable()) worker.join();
        if (registry) registry->shutdown();
    }
    GameAdmission prepare() {
        if (direct_admission) return *direct_admission;
        const auto redirect = registry->prepare(room);
        check(redirect.size() == 1 && redirect[0].recipient == 77 && redirect[0].frame.wire_type == 22,"redirect_missing");
        const auto& bytes = redirect[0].frame.payload;
        check(bytes.size() == 18 && read_le(View(bytes).subspan(4,2)) == service->bound_port(),"redirect_endpoint_wrong");
        GameAdmission admission{0,room.key,actor,{},read_le(View(bytes).subspan(6,4)),{}};
        std::copy(bytes.begin()+10,bytes.end(),admission.opaque8.begin()); return admission;
    }
    void closed_with(std::string_view reason) {
        observed.wait([&] { return observed.cleanup == 1 && std::any_of(observed.logs.begin(),observed.logs.end(),[&](const auto& line) {
            return line.find(reason) != line.npos;
        }); });
        check(!registry->has_room(room.key),"closed_game_plan_still_registered");
    }
};
void turn(Peer& peer,std::uint8_t actor) {
    check(peer.receive() == Bytes({0x10,0x40,0x34,0x12,actor,1,0,0xa2}),"4010_turn_sequence_wrong");
    check(peer.receive() == Bytes({0x0f,0x42,0x34,0x12,0xff,0xff}),"420f_status_phase_missing");
}
void movement(Peer& peer,std::uint16_t start,std::uint8_t steps = 1,std::uint8_t direction = 1) {
    const auto bytes = peer.receive();
    check(bytes.size() == 28 && read_le(View(bytes).first(2)) == 0x4011 &&
        read_le(View(bytes).subspan(2,2)) == server_id && read_le(View(bytes).subspan(4,2)) == start &&
        bytes[6] == 1 && bytes[7] == steps && bytes[8] == steps && bytes[9] == 0xf9 && bytes[10] == 9 &&
        read_le(View(bytes).subspan(20,4)) == 0xd3c3b3a3U && read_le(View(bytes).subspan(24,4)) == 0,"4011_resource_route_wrong");
    for (std::size_t i = 0; i < steps; ++i)
        check(((bytes[11+i/4] >> (2*(i%4)))&3U) == direction,"fixture_route_direction_wrong");
}
void opening(Scenario& scenario,Peer& peer,const GameAdmission& admission,std::uint8_t steps = 1) {
    peer.send_frame(encode_game_admission(admission,ClientVersion::richonline));
    const auto admitted = peer.receive_frame();
    check(admitted.wire_type == 1 && admitted.payload.empty(),"admission_ack_must_precede_init");
    const auto init = peer.receive();
    check(init.size() == 52 && read_le(View(init).first(2)) == 0x4000 && read_le(View(init).subspan(2,2)) == server_id &&
        read_le(View(init).subspan(20,2)) == scenario.actor && read_le(View(init).subspan(36,2)) == 0xffff,"4000_identity_wrong");
    peer.send(Bytes{1,0}); peer.send(Bytes{0,0});
    const auto sync = peer.receive();
    check(sync.size() == 36 && read_le(View(sync).first(2)) == 0x4004 && read_le(View(sync).subspan(4,4)) == initial_counter &&
        read_le(View(sync).subspan(12,4)) == 20000 && read_le(View(sync).subspan(24,4)) == 100000,"4004_resource_snapshot_wrong");
    turn(peer,1); movement(peer,236,steps);
}
void full_round_uses_real_wire_sequence(const std::filesystem::path& resources) {
    Scenario scenario(resources,false); const auto admission = scenario.prepare(); Peer peer(scenario.service->bound_port());
    opening(scenario,peer,admission);
    peer.send(request(0x11,initial_counter+1,235)); turn(peer,0);
    peer.send(request(0x10,initial_counter+2,0,4)); movement(peer,115);
    peer.send(request(0x11,initial_counter+2,114)); turn(peer,1); movement(peer,235);
    peer.close(); scenario.closed_with("reason=peer_closed"); scenario.stop();
    const std::lock_guard lock(scenario.observed.mutex);
    const auto& landings = scenario.observed.landings;
    check(landings.size() == 2 && landings[0].actor_slot == 1 && landings[0].position == 235 &&
        landings[1].actor_slot == 0 && landings[1].position == 114 && scenario.observed.events == 0 && scenario.observed.cleanup == 1,
        "full_round_landing_or_cleanup_not_once");
}
void waiting_landing_needs_explicit_fixture_event(const std::filesystem::path& resources) {
    Scenario scenario(resources,true); const auto admission = scenario.prepare(); Peer peer(scenario.service->bound_port());
    opening(scenario,peer,admission); peer.send(request(0x11,initial_counter+1,235));
    scenario.observed.wait([&] { return scenario.observed.landings.size() == 1; });
    peer.send(request(0x55,initial_counter+1,0)); turn(peer,0);
    peer.send(request(0x11,initial_counter+2,235));
    scenario.closed_with("reason=richonline_boss_stop_out_of_phase"); scenario.stop();
    const std::lock_guard lock(scenario.observed.mutex);
    check(scenario.observed.landings.size() == 1 && scenario.observed.events == 1 && scenario.observed.cleanup == 1,
        "duplicate_stop_repeated_landing");
}
void game_id_is_not_the_action_counter(const std::filesystem::path& resources) {
    Scenario scenario(resources,false); const auto admission = scenario.prepare(); Peer peer(scenario.service->bound_port());
    opening(scenario,peer,admission); peer.send(request(0x11,server_id,235));
    scenario.closed_with("reason=richonline_game_action_context_mismatch"); scenario.stop();
    const std::lock_guard lock(scenario.observed.mutex);
    check(scenario.observed.landings.empty() && scenario.observed.cleanup == 1,"wrong_counter_reached_gameplay");
}
void actual_boss_landings_and_shop_exit_precede_next_turn(const std::filesystem::path& resources) {
    for (const std::uint8_t steps : {std::uint8_t{1},std::uint8_t{3}}) {
        Scenario scenario(resources,false,true,steps);
        const auto admission = scenario.prepare(); Peer peer(scenario.service->bound_port());
        opening(scenario,peer,admission,steps);
        const auto endpoint = static_cast<std::uint16_t>(236-steps);
        peer.send(request(0x11,initial_counter+1,endpoint));
        check(peer.receive() == Bytes({0x13,0x40,0x34,0x12,static_cast<std::uint8_t>(endpoint),0}),"actual_landing_4013_missing");
        if (steps == 3)
            check(peer.receive() == Bytes({0x31,0x40,0x34,0x12,0xff}),"actual_boss_shop_exit_missing");
        turn(peer,0);
        peer.close(); scenario.closed_with("reason=peer_closed"); scenario.stop();
        const std::lock_guard lock(scenario.observed.mutex);
        check(scenario.observed.landings.size() == 1 && scenario.observed.landings.front().actor_slot == 1 &&
            scenario.observed.landings.front().position == endpoint && scenario.observed.landings.front().property_ref == -1 &&
            scenario.observed.landings.front().synthetic_actor && scenario.observed.events == 0 && scenario.observed.cleanup == 1,
            "actual_landing_lifecycle_wrong");
        if (steps == 3) check(scenario.observed.landings.front().static_type == 10,"three_step_landing_not_real_shop");
    }
}
void wrong_endpoint_never_reaches_actual_resolver(const std::filesystem::path& resources) {
    Scenario scenario(resources,false,true); const auto admission = scenario.prepare(); Peer peer(scenario.service->bound_port());
    opening(scenario,peer,admission); peer.send(request(0x11,initial_counter+1,234));
    scenario.closed_with("reason=richonline_boss_endpoint_mismatch"); scenario.stop();
    const std::lock_guard lock(scenario.observed.mutex);
    check(scenario.observed.landings.empty() && scenario.observed.cleanup == 1,"wrong_endpoint_reached_actual_resolver");
}
void actual_reward_drives_controlled_dice_without_another_roll(const std::filesystem::path& resources) {
    const auto chance = std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources));
    const auto cards = std::make_shared<RichonlineBossCards>(chance,server_id,
        RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
    Scenario scenario(resources,false,true,1,cards);
    const auto admission = scenario.prepare(); Peer peer(scenario.service->bound_port());
    opening(scenario,peer,admission);
    peer.send(request(0x11,initial_counter+1,235));
    check(peer.receive() == Bytes({0x13,0x40,0x34,0x12,235,0}),"cards_boss_first_stop_missing");
    turn(peer,0);
    auto selected = request(103,initial_counter+2,0,4); selected.resize(12,0);
    selected[6] = 3; selected[7] = 0xa9;
    peer.send(selected);
    check(peer.receive() == Bytes({0x0b,0x40,0x34,0x12,1}),"empty_card_slot_did_not_restore_controls");
    peer.send(request(22,initial_counter+2,0xa903));
    check(peer.receive() == Bytes({0x0b,0x40,0x34,0x12,1}),"paid_dice_did_not_restore_controls");
    peer.send(request(0x10,initial_counter+2,0,4)); movement(peer,115);
    peer.send(request(0x11,initial_counter+2,114));
    check(peer.receive() == Bytes({0x13,0x40,0x34,0x12,114,0}),"chance_landing_stop_missing");
    check(peer.receive() == Bytes({0x96,0x40,0x34,0x12,17,0,0xa5,0x5a,0x0e,0x04,0,0}),"chance_card_reward_wrong");
    turn(peer,1); movement(peer,235);
    peer.send(request(0x11,initial_counter+3,234));
    check(peer.receive() == Bytes({0x13,0x40,0x34,0x12,234,0}),"cards_boss_second_stop_missing");
    turn(peer,0);
    selected[2] = static_cast<std::uint8_t>((initial_counter+4)&255U);
    selected[3] = static_cast<std::uint8_t>((initial_counter+4)>>8U);
    peer.send(selected);
    check(peer.receive() == Bytes({0xb7,0x40,0x34,0x12,0,0}),"controlled_dice_consumption_missing");
    movement(peer,114,3,0);
    peer.send(selected);
    scenario.closed_with("reason=richonline_boss_card_out_of_phase"); scenario.stop();
    check(std::all_of(cards->inventory().begin(),cards->inventory().end(),[](const auto& slot) {
        return slot == RichonlineChanceCardSlot{-1,0};
    }),"controlled_dice_inventory_not_consumed_once");
    const std::lock_guard lock(scenario.observed.mutex);
    check(scenario.observed.cleanup == 1 && scenario.observed.events == 0 && scenario.observed.landings.size() == 2,
        "controlled_dice_duplicate_repeated_landing_or_cleanup");
    for (const auto reason : {"controlled_dice_slot_unavailable","authenticated_payment_unavailable"})
        check(std::count_if(scenario.observed.logs.begin(),scenario.observed.logs.end(),[&](const auto& line) {
            return line.find(reason) != line.npos;
        }) == 1,"controlled_dice_rejection_log_not_once");
}
void human_purchase_closes_once_and_tolerates_a_late_click(const std::filesystem::path& resources) {
    for (const bool accept_before_deadline : {false,true}) {
        std::atomic<std::int64_t> elapsed_ms{0};
        const auto property = std::make_shared<RichonlineBossProperty>(resources,server_id,
            std::array<std::uint32_t,2>{20000,100000},load_richonline_boss_stage(resources,"BS_1_1.emp"));
        property->enable_human_decisions(std::chrono::milliseconds{5000},[&] {
            return RichonlineBossProperty::Clock::time_point{}+std::chrono::milliseconds{elapsed_ms.load()};
        });
        Scenario scenario(resources,false,true,1,{},property);
        const auto admission = scenario.prepare(); Peer peer(scenario.service->bound_port());
        opening(scenario,peer,admission);
        peer.send(request(0x11,initial_counter+1,235));
        check(peer.receive() == Bytes({0x13,0x40,0x34,0x12,235,0}),"purchase_boss_stop_missing");
        turn(peer,0);
        peer.send(request(0x10,initial_counter+2,0,4)); movement(peer,233);
        peer.send(request(0x11,initial_counter+2,232));
        check(peer.receive() == Bytes({0x13,0x40,0x34,0x12,232,0}),"human_purchase_prompt_missing");
        auto accept = request(0x20,initial_counter+2,0,4);
        accept.insert(accept.end(),{1,0xa5,0x5a,0xc3});
        if (accept_before_deadline) peer.send(accept);
        else elapsed_ms.store(5000);
        check(peer.receive() == Bytes({0x20,0x40,0x34,0x12,static_cast<std::uint8_t>(accept_before_deadline)}),
            "human_purchase_resolution_wrong");
        turn(peer,1); movement(peer,235);
        elapsed_ms.store(5000);
        peer.send(accept);
        peer.send(request(0x11,initial_counter+3,234));
        check(peer.receive() == Bytes({0x13,0x40,0x34,0x12,234,0}),"late_purchase_click_repeated_response_or_closed_session");
        turn(peer,0);
        peer.close(); scenario.closed_with("reason=peer_closed"); scenario.stop();
        check(property->cash() == std::array<std::uint32_t,2>{accept_before_deadline ? 19900U : 20000U,100000U} &&
            property->owner(216) == (accept_before_deadline ? std::optional<std::uint8_t>{0} : std::nullopt),
            "purchase_timeout_or_duplicate_changed_ledger");
        const std::lock_guard lock(scenario.observed.mutex);
        check(scenario.observed.cleanup == 1 && scenario.observed.events == (accept_before_deadline ? 1U : 0U) &&
            scenario.observed.landings.size() == 3,"purchase_late_click_reentered_decision_or_cleanup");
        const auto& human = scenario.observed.landings[1];
        check(human.actor_slot == 0 && human.position == 232 && human.property_ref == 216 &&
            human.static_type == 33 && !human.synthetic_actor,"purchase_used_wrong_real_property");
    }
}
}
int main(int argc,char** argv) {
    try {
        check(argc == 2,"resource_path_required"); const Network network;
        const std::filesystem::path resources(argv[1]);
        full_round_uses_real_wire_sequence(resources); waiting_landing_needs_explicit_fixture_event(resources);
        game_id_is_not_the_action_counter(resources);
        actual_boss_landings_and_shop_exit_precede_next_turn(resources); wrong_endpoint_never_reaches_actual_resolver(resources);
        actual_reward_drives_controlled_dice_without_another_roll(resources);
        human_purchase_closes_once_and_tolerates_a_late_click(resources);
        std::cout << "PASS encrypted TCP real BOSS landing/shop/cards/purchase timeout and lifecycle fixtures; no complete gameplay claim\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
