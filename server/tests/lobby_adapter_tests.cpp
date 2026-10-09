#include "server_lobby_adapter.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
template<class Action> void rejects(Action action, std::string_view expected) {
    try { action(); }
    catch (const CodecError& error) {
        require(error.what() == expected, "unexpected_error_code");
        return;
    }
    throw std::runtime_error("expected_rejection");
}
void put(Bytes& data, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) data.at(offset + i) = static_cast<std::uint8_t>(value >> (i * 8));
}
BootstrapBlobs fixture() {
    BootstrapBlobs blobs{};
    blobs.provenance = "Deterministic adapter test fixture; opaque bytes have no asserted protocol semantics.";
    blobs.game_capacity = 8;
    blobs.player_capacity = 100;
    blobs.setting_text = "14";
    blobs.stage_progress = {1, 1, 2, 0};
    const auto bits = std::bit_cast<std::uint64_t>(2.5);
    for (std::size_t i = 0; i < 8; ++i)
        blobs.unknown_completion[20 + i] = static_cast<std::uint8_t>(bits >> (i * 8));
    blobs.unknown_login_result[8] = 0xa1;
    blobs.unknown_identity_record[8] = 0xb2;
    blobs.unknown_profile_record[4] = 0xc3;
    return blobs;
}
std::filesystem::path scratch() {
    const auto base = std::filesystem::temp_directory_path() / L"richonline-lobby-adapter-tests";
    for (std::uint32_t i = 1; i < 10000; ++i) {
        const auto path = base / std::to_wstring(i);
        if (std::filesystem::create_directories(path)) return path;
    }
    throw std::runtime_error("test_scratch_exhausted");
}
void bootstrap_divisor_requires_explicit_positive_policy() {
    auto blobs = fixture();
    validate_bootstrap_blobs(blobs);
    blobs.unknown_completion.fill(0);
    rejects([&] { validate_bootstrap_blobs(blobs); }, "bootstrap_exchange_divisor_must_be_finite_positive");
}
void owned_rp_certificate_is_equipped_in_catalog_and_channel() {
    Storage storage(scratch() / "rp.sqlite3");
    const auto account=storage.dispatch("accounts.create",{{"username","rp-test"},{"password","rp-secret"}}).at("account");
    const auto id=account.at("role_id").get<std::uint32_t>();
    const auto now=std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    storage.ensure_test_rp_certificate("rp-test",now);
    ServerLobbyAdapter adapter(storage,fixture());
    const auto callbacks=adapter.callbacks();
    const LobbyLogin login{"rp-test",41};
    const auto catalog=callbacks.login_responses(login);
    require(read_le(View(catalog.front().payload).subspan(4+80+13*4,4))==13,
        "owned_rp_certificate_missing_from_role_equipment");
    Bytes selection(4); put(selection,0,id);
    callbacks.authenticated_request(login,{34,selection});
    const auto channel=callbacks.authenticated_request(login,{7,{0,0,0,0}});
    require(read_le(View(channel[1].payload).subspan(144+13*4,4))==13,
        "owned_rp_certificate_missing_from_profile_equipment");
    require(channel[2].payload.size()==12 && read_le(View(channel[2].payload).first(4))==1 &&
        read_le(View(channel[2].payload).subspan(4,4))==13,
        "equipped_rp_certificate_missing_from_inventory");
}
void login_and_channel_use_database_values_and_new_offsets() {
    const auto path = scratch();
    Storage storage(path / L"accounts.sqlite3");
    auto account = storage.dispatch("accounts.create", {{"username", "adapter-test"}, {"password", "adapter-secret"}}).at("account");
    const auto role_id = account.at("role_id").get<std::uint32_t>();
    require(role_id > 0, "fixture_role_id_invalid");
    constexpr std::uint32_t escapes = 0x123456;
    account = storage.dispatch("accounts.update", {{"role_id", role_id},
        {"expected", {{"escapes", account.at("escapes")}}}, {"changes", {{"escapes", escapes}}},
        {"reason", "isolated role/profile escape counter fixture"}}).at("account");
    auto blobs = fixture();
    std::fill_n(blobs.unknown_role_record.begin()+28, 8, 0xa5);
    std::string events;
    ServerLobbyAdapter adapter(storage, blobs, [&](const std::string& event, const nlohmann::json&) { events += event; });
    const auto callbacks = adapter.callbacks();
    const Bytes password{'a','d','a','p','t','e','r','-','s','e','c','r','e','t'};
    require(callbacks.verify_credentials("adapter-test", password), "database_credentials_rejected");
    const LobbyLogin login{"adapter-test", 0x10203040};
    const auto first = callbacks.login_responses(login);
    require(first.size() == 3 && first[0].wire_type == 67 && first[1].wire_type == 1 && first[2].wire_type == 3,
            "login_response_sequence_wrong");
    require(first[0].payload.size() == 212 && read_le(View(first[0].payload).first(4)) == 1,
            "role_catalog_layout_wrong");
    require(read_le(View(first[0].payload).subspan(4, 4)) == role_id, "role_catalog_id_not_database_value");
    require(read_le(View(first[0].payload).subspan(4+32, 4)) == escapes,
            "role_catalog_escape_counter_not_database_value");
    require(read_le(View(first[0].payload).subspan(4+28, 4)) == 0xa5a5a5a5U,
            "role_catalog_ignored_word_overwritten");
    require(first[1].payload.size() == 16 && read_le(View(first[1].payload).first(4)) == role_id && first[1].payload[8] == 0xa1,
            "login_result_opaque_bytes_lost");
    require(first[2].payload.size() == 80 && read_le(View(first[2].payload).subspan(32, 4)) == 0 &&
            read_le(View(first[2].payload).subspan(48, 4)) == 8 && read_le(View(first[2].payload).subspan(52, 4)) == 100,
            "new_channel_record_wrong");
    Bytes request(4);
    put(request, 0, role_id);
    const auto selected = callbacks.authenticated_request(login, {34, request});
    require(selected.size() == 1 && selected[0].wire_type == 70 && selected[0].payload == request,
            "native_selected_role_confirmation_missing");
    const auto entered = callbacks.authenticated_request(login, {7, {0,0,0,0}});
    const std::uint32_t expected[]{9, 7, 2, 100, 103, 106, 30};
    require(entered.size() == std::size(expected), "channel_response_count_wrong");
    for (std::size_t i = 0; i < entered.size(); ++i) require(entered[i].wire_type == expected[i], "channel_response_sequence_wrong");
    require(entered[0].payload.size() == 16 && read_le(View(entered[0].payload).first(4)) == role_id &&
            read_le(View(entered[0].payload).subspan(4, 4)) == 0 && entered[0].payload[8] == 0xb2, "identity_record_wrong");
    const auto& profile = entered[1].payload;
    require(profile.size() == 272 && read_le(View(profile).first(4)) == role_id && profile[4] == 0xc3,
            "profile_id_or_opaque_bytes_wrong");
    require(read_le(View(profile).subspan(8, 4)) == 0 && read_le(View(profile).subspan(12, 4)) == 0xffffffffU &&
            read_le(View(profile).subspan(72, 4)) == 0, "new_profile_channel_game_and_bool_wrong");
    require(read_le(View(profile).subspan(44, 4)) == 0xfffffffeU, "profile_constructor_state_not_preserved");
    require(read_le(View(profile).subspan(104, 4)) == account.at("experience").get<std::uint32_t>(), "new_profile_experience_offset_wrong");
    require(read_le(View(profile).subspan(108, 4)) == escapes &&
            read_le(View(profile).subspan(108, 4)) == read_le(View(first[0].payload).subspan(4+32, 4)),
            "role_catalog_and_profile_escape_counters_disagree");
    require(entered[2].payload.size() == 4 && entered[3].payload.size() == 32 && entered[6].payload.size() == 28,
            "bootstrap_fixed_sizes_wrong");
    require(entered[4].payload == Bytes({1, 1, 2, 0}) && entered[5].payload == Bytes({'1','4',0}), "bootstrap_strings_wrong");
    rejects([&] { callbacks.authenticated_request(login, {34, {0,0,0,0}}); }, "lobby_role_not_owned");
    rejects([&] { callbacks.authenticated_request(login, {34, {1}}); }, "lobby_role_selection_length_invalid");
    rejects([&] { callbacks.authenticated_request(login, {1234, {}}); }, "lobby_authenticated_request_unsupported");
    require(events.find("adapter-secret") == std::string::npos && events.find("adapter-test") == std::string::npos,
            "credentials_or_username_logged");
}
void full_session_authenticates_big5_username_from_real_database() {
    const auto path = scratch();
    Storage storage(path / L"big5.sqlite3");
    const auto record = storage.dispatch("accounts.create", {{"username", "\xe6\xb8\xac\xe8\xa9\xa6"}, {"password", "wire-secret"}}).at("account");
    const auto role_id = record.at("role_id").get<std::uint32_t>();
    ServerLobbyAdapter adapter(storage, fixture());
    RichLobbySession session(ServerLobbyOptions{"127.0.0.1", 0}.transport(), adapter.callbacks());
    static_cast<void>(session.start());
    const auto public_reply = encode_frame({759, {0x71,0,0,0}}, {Channel::lobby_c2s, std::nullopt, ClientVersion::richonline});
    Bytes payload(144, 0xca);
    std::fill_n(payload.begin(), 12, 0);
    const Bytes name{0xb4,0xfa,0xb8,0xd5,0};
    const Bytes password{'w','i','r','e','-','s','e','c','r','e','t',0};
    std::copy(name.begin(), name.end(), payload.begin() + 12);
    std::copy(password.begin(), password.end(), payload.begin() + 76);
    put(payload, 140, 0x12345678);
    auto input = public_reply;
    const auto login = encode_frame({58, payload}, {Channel::lobby_c2s, 219, ClientVersion::richonline});
    input.insert(input.end(), login.begin(), login.end());
    Bytes selection(4);
    put(selection, 0, role_id);
    const auto select = encode_frame({34, selection}, {Channel::lobby_c2s, 219, ClientVersion::richonline});
    input.insert(input.end(), select.begin(), select.end());
    const auto channel = encode_frame({7, {0,0,0,0}}, {Channel::lobby_c2s, 219, ClientVersion::richonline});
    input.insert(input.end(), channel.begin(), channel.end());
    const auto output = session.feed(input);
    const std::uint32_t types[]{67,1,3,70,9,7,2,100,103,106,30};
    const std::size_t sizes[]{212,16,80,4,16,272,4,32,4,3,28};
    require(output.size() == std::size(types) && session.state() == LobbyState::authenticated, "full_session_failed");
    for (std::size_t i = 0; i < output.size(); ++i) {
        const auto frame = decode_frame(output[i], {Channel::lobby_s2c, 219, ClientVersion::richonline});
        require(frame.wire_type == types[i] && frame.payload.size() == sizes[i], "full_session_frame_wrong");
    }
    session.finish();
}
void existing_room_snapshot_precedes_channel_completion() {
    Storage storage(scratch() / "late.sqlite3");
    const auto create = [&](const char* user) {
        return storage.dispatch("accounts.create", {{"username",user},{"password","fixture"}})
            .at("account").at("role_id").get<std::uint32_t>();
    };
    const auto owner = create("owner"), newcomer = create("newcomer");
    auto blobs = fixture(); blobs.room_unknown_prefix = 0x12345678;
    ServerLobbyAdapter adapter(storage,blobs);
    const auto a = adapter.callbacks(), b = adapter.callbacks();
    Bytes selection(4); put(selection,0,owner);
    static_cast<void>(a.authenticated_request({"owner",1},{34,selection}));
    static_cast<void>(a.authenticated_request({"owner",1},{7,{0,0,0,0}}));
    Bytes room(128); room[0]='r'; put(room,40,2); put(room,72,2); put(room,124,1);
    static_cast<void>(a.authenticated_request({"owner",1},{3,room}));
    static_cast<void>(a.authenticated_request({"owner",1},{5,{}}));
    put(selection,0,newcomer);
    static_cast<void>(b.authenticated_request({"newcomer",2},{34,selection}));
    const auto frames = b.authenticated_request({"newcomer",2},{7,{0,0,0,0}});
    require(frames.back().wire_type == 30,"channel_completion_precedes_existing_room_snapshot");
    const auto snapshot = std::find_if(frames.begin(),frames.end(),[](const auto& frame) { return frame.wire_type==5; });
    require(snapshot!=frames.end() && std::distance(snapshot,frames.end())>=4 &&
            (snapshot+1)->wire_type==12 && (snapshot+2)->wire_type==13,
            "existing_room_membership_and_readiness_not_before_completion");
}
void channel_requires_confirmed_role_and_catalog_key() {
    Storage storage(scratch() / "selected-role.sqlite3");
    const auto actor = storage.dispatch("accounts.create", {{"username","selected-role"},{"password","fixture"}})
        .at("account").at("role_id").get<std::uint32_t>();
    ServerLobbyAdapter adapter(storage,fixture());
    const auto callbacks = adapter.callbacks();
    const LobbyLogin login{"selected-role",3};
    rejects([&] { callbacks.authenticated_request(login,{7,{0,0,0,0}}); },"richonline_role_selection_required");
    Bytes selection(4); put(selection,0,actor);
    const auto confirmed = callbacks.authenticated_request(login,{34,selection});
    require(confirmed.size()==1 && confirmed.front().wire_type==70 && confirmed.front().payload==selection,
        "role_confirmation_did_not_echo_owned_catalog_identity");
    rejects([&] { callbacks.authenticated_request(login,{7,{0}}); },"richonline_channel_selection_length_invalid");
    rejects([&] { callbacks.authenticated_request(login,{7,{1,0,0,0}}); },"richonline_channel_not_in_catalog");
    const auto admitted = callbacks.authenticated_request(login,{7,{0,0,0,0}});
    require(admitted.front().wire_type==9 && read_le(View(admitted.front().payload).first(4))==actor,
        "channel_admission_lost_selected_identity");
    rejects([&] { callbacks.authenticated_request(login,{7,{0,0,0,0}}); },"richonline_channel_already_entered");
}
void three_channels_have_separate_room_directories() {
    Storage storage(scratch() / "channels.sqlite3");
    auto blobs = fixture(); blobs.room_unknown_prefix = 9;
    for (std::uint32_t key = 0; key < 3; ++key)
        blobs.channels.push_back({key,"channel-" + std::to_string(key),8,100,0,1,0,1e9,0,999,{}});
    ServerLobbyAdapter adapter(storage,blobs);
    const auto create = [&](const char* name) {
        return storage.dispatch("accounts.create",{{"username",name},{"password","fixture"}})
            .at("account").at("role_id").get<std::uint32_t>();
    };
    const auto actor0 = create("channel-zero"), actor1 = create("channel-one"), actor2 = create("channel-two");
    const auto a = adapter.callbacks(), b = adapter.callbacks(), c = adapter.callbacks(), observer = adapter.callbacks();
    const auto catalog = a.login_responses({"channel-zero",1});
    require(catalog.size()==5 && read_le(View(catalog[1].payload).subspan(4,4))==3,"three_channel_catalog_count_wrong");
    for (std::uint32_t key=0;key<3;++key)
        require(catalog[key+2].wire_type==3 && catalog[key+2].payload.size()==80 &&
            read_le(View(catalog[key+2].payload).subspan(32,4))==key,"channel_catalog_not_separate_dense_records");
    const auto enter = [&](const LobbyCallbacks& cb,const char* user,std::uint32_t role,std::uint32_t key) {
        Bytes selected(4), channel(4); put(selected,0,role); put(channel,0,key);
        cb.authenticated_request({user,1},{34,selected});
        return cb.authenticated_request({user,1},{7,channel});
    };
    require(read_le(View(enter(a,"channel-zero",actor0,0).front().payload).subspan(4,4))==0,"identity_channel_zero_wrong");
    require(read_le(View(enter(b,"channel-one",actor1,1).front().payload).subspan(4,4))==1,"identity_channel_one_wrong");
    require(read_le(View(enter(c,"channel-two",actor2,2).front().payload).subspan(4,4))==2,"identity_channel_two_wrong");
    require(adapter.channel_player_count(0)==1 && adapter.channel_player_count(1)==1 && adapter.channel_player_count(2)==1,
        "channel_player_counts_mixed");
    require(a.drain_outbound().empty() && b.drain_outbound().empty(),"profiles_crossed_channel_boundary");
    Bytes room(128); room[0]='r'; put(room,40,2); put(room,72,2); put(room,124,1);
    a.authenticated_request({"channel-zero",1},{3,room});
    b.authenticated_request({"channel-one",1},{3,room});
    require(c.drain_outbound().empty(),"new_room_crossed_channel_boundary");
    const auto observer_id=create("channel-observer");
    const auto snapshot=enter(observer,"channel-observer",observer_id,1);
    const auto room_count=std::count_if(snapshot.begin(),snapshot.end(),[](const Frame& f){return f.wire_type==5;});
    require(room_count==1,"observer_received_other_channel_rooms");
    require(!b.drain_outbound().empty() && a.drain_outbound().empty(),"observer_profile_went_to_wrong_channel");
    const auto duplicate=adapter.callbacks();
    rejects([&]{enter(duplicate,"channel-zero",actor0,2);},"richonline_actor_already_online_or_invalid");
    a.disconnected();
    require(adapter.channel_player_count(0)==0 && adapter.channel_player_count(1)==2 && adapter.channel_player_count(2)==1,
        "channel_player_counts_not_updated_on_disconnect");
    require(observer.drain_outbound().empty() && b.drain_outbound().empty(),"disconnect_crossed_channel_boundary");
}
void channel_catalog_rejects_invalid_keys_and_capacities() {
    auto blobs=fixture();
    blobs.channels.push_back({1,"channel",8,100,0,1,0,1e9,0,999,{}});
    rejects([&]{validate_bootstrap_blobs(blobs);},"bootstrap_channel_keys_must_be_dense");
    blobs.channels.front().key=0;
    blobs.channels.front().player_capacity=1;
    rejects([&]{validate_bootstrap_blobs(blobs);},"bootstrap_channel_capacity_invalid");
    blobs.channels.front().player_capacity=100;
    blobs.channels.front().name_utf8="channel\nChannelID=9";
    rejects([&]{validate_bootstrap_blobs(blobs);},"bootstrap_channel_name_invalid");
    blobs.channels.front().name_utf8="channel";
    blobs.channels.front().min_gold=2; blobs.channels.front().max_gold=1;
    rejects([&]{validate_bootstrap_blobs(blobs);},"bootstrap_channel_restrictions_invalid");
}
}
int main() {
    try {
        bootstrap_divisor_requires_explicit_positive_policy();
        owned_rp_certificate_is_equipped_in_catalog_and_channel();
        three_channels_have_separate_room_directories();
        channel_catalog_rejects_invalid_keys_and_capacities();
        login_and_channel_use_database_values_and_new_offsets();
        full_session_authenticates_big5_username_from_real_database();
        existing_room_snapshot_precedes_channel_completion();
        channel_requires_confirmed_role_and_catalog_key();
        std::cout << "lobby adapter tests PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
