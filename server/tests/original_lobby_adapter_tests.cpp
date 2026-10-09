#include "original_lobby_adapter.hpp"
#include "original_bank_fixture.hpp"

#include <algorithm>
#include <bit>
#include <filesystem>
#include <iostream>
#include <string_view>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        require(error.what() == code, "unexpected_error_code"); return;
    }
    throw std::runtime_error("expected_rejection");
}
OriginalLobbyPolicy policy() {
    OriginalLobbyPolicy result{"Test-only nonzero opaque templates; no historical packet claim.",
        Bytes(220,0xa1),Bytes(208,0xb2),Bytes(268,0xc3),Bytes(16,0xd4),Bytes(16,0xe5),Bytes(original_bank_test::config.begin(),original_bank_test::config.end()),Bytes(28,0x27),
        3,8,100,32,2,{1,1,2,0},"4096",14};
    result.room_template[124] |= 0x40;
    return result;
}
std::filesystem::path scratch() {
    const auto base = std::filesystem::temp_directory_path() / L"original-lobby-adapter-tests";
    for (std::uint32_t i = 1; i < 10000; ++i) {
        const auto path = base / std::to_wstring(i);
        if (std::filesystem::create_directories(path)) return path;
    }
    throw std::runtime_error("scratch_exhausted");
}
Bytes id_bytes(std::uint32_t id) { Bytes data; append_le(data,id,4); return data; }
std::uint32_t u32(const Bytes& data,std::size_t offset) { return read_le(View(data).subspan(offset,4)); }
double f64(const Bytes& data,std::size_t offset) {
    std::uint64_t bits = 0;
    for (std::size_t i = 0; i < 8; ++i) bits |= static_cast<std::uint64_t>(data.at(offset+i)) << (8*i);
    return std::bit_cast<double>(bits);
}
void preserved(const Bytes& actual,const Bytes& source,
               std::initializer_list<std::pair<std::size_t,std::size_t>> replaced) {
    require(actual.size() == source.size(),"template_size_changed");
    for (std::size_t offset = 0; offset < source.size(); ++offset) {
        const auto known = std::any_of(replaced.begin(),replaced.end(),[&](const auto& span) {
            return offset >= span.first && offset < span.first + span.second;
        });
        if (!known) require(actual[offset] == source[offset],"opaque_template_byte_lost");
    }
}
void exact_packets_and_database_ownership(Storage& storage,const Json& account,const Json& other) {
    const auto config = policy();
    auto callbacks = make_original_lobby_callbacks(storage,config);
    const auto username = account.at("username").get<std::string>();
    const auto id = account.at("role_id").get<std::uint32_t>();
    const LobbyLogin login{username,0x1234,0xdeadbeef};
    const auto password = client_text("\xe5\xaf\x86\xe7\xa0\x81",ClientProfile::original);
    require(!callbacks.verify_credentials(username,Bytes{'b','a','d'}),"bad_password_accepted");
    rejects([&] { callbacks.login_responses(login); },"original_lobby_not_authenticated");
    require(callbacks.verify_credentials(username,password),"original_password_rejected");
    rejects([&] { callbacks.authenticated_request(login,{34,id_bytes(id)}); },"original_lobby_catalog_required");
    const auto catalog = callbacks.login_responses(login);
    require(catalog.size() == 2 && catalog[0].wire_type == 67 && catalog[1].wire_type == 1,"login_order_wrong");
    require(catalog[0].payload.size() == 212 && u32(catalog[0].payload,0) == 1,"catalog_count_wrong");
    const Bytes role(catalog[0].payload.begin()+4,catalog[0].payload.end());
    preserved(role,config.role_template,{{0,28},{36,44}});
    for (const auto& [offset,field] : std::initializer_list<std::pair<std::size_t,const char*>>{
             {0,"role_id"},{4,"model"},{8,"purchase_score"},{12,"level"},{16,"wins"},{20,"losses"},{24,"draws"},{44,"experience"}})
        require(u32(role,offset) == account.at(field).get<std::uint32_t>(),"role_field_offset_wrong");
    require(f64(role,36) == account.at("gold").get<double>(),"role_gold_wrong");
    const auto name = client_text(account.at("name").get<std::string>(),ClientProfile::original);
    require(std::equal(name.begin(),name.end(),role.begin()+48) && role[48+name.size()] == 0,"role_gbk_name_wrong");
    preserved(catalog[1].payload,config.login_template,{{0,8}});
    require(u32(catalog[1].payload,0) == id && u32(catalog[1].payload,4) == 4,"login_identity_wrong");
    rejects([&] { callbacks.login_responses(login); },"original_lobby_duplicate_catalog");
    rejects([&] { callbacks.authenticated_request({other.at("username").get<std::string>(),0},{34,id_bytes(id)}); },
            "original_lobby_not_authenticated");
    rejects([&] { callbacks.authenticated_request(login,{34,id_bytes(other.at("role_id").get<std::uint32_t>())}); },
            "original_lobby_role_not_owned");
    rejects([&] { callbacks.authenticated_request(login,{34,{1}}); },"original_lobby_selection_length_invalid");
    rejects([&] { callbacks.authenticated_request(login,{1234,{}}); },"original_lobby_request_unsupported");
    rejects([&] { callbacks.authenticated_request(login,{105,{'1','2',0}}); },"original_lobby_selection_required");
    rejects([&] { callbacks.authenticated_request(login,{61,Bytes(8)}); },"original_lobby_selection_required");
    rejects([&] { callbacks.authenticated_request(login,{42,Bytes(24)}); },"original_lobby_selection_required");
    const auto frames = callbacks.authenticated_request(login,{34,id_bytes(id)});
    const std::uint32_t types[]{3,9,7,140,4,2,100,103,106,30};
    const std::size_t sizes[]{220,16,268,8,4,4,32,4,5,28};
    require(frames.size() == std::size(types),"bootstrap_count_wrong");
    for (std::size_t i=0;i<frames.size();++i)
        require(frames[i].wire_type == types[i] && frames[i].payload.size() == sizes[i],"bootstrap_order_or_size_wrong");
    preserved(frames[0].payload,config.room_template,{{32,4},{48,8},{124,4},{212,8}});
    require(u32(frames[0].payload,124) == (u32(config.room_template,124) & ~0x40U),"room_extension_flag_not_cleared_or_other_flags_lost");
    require(u32(frames[0].payload,212) == 0 && u32(frames[0].payload,216) == 0,"fixed_room_extension_fields_wrong");
    require(u32(frames[0].payload,32) == 3 && u32(frames[0].payload,48) == 8 && u32(frames[0].payload,52) == 100,"room_fields_wrong");
    preserved(frames[1].payload,config.identity_template,{{0,8}});
    require(u32(frames[1].payload,0) == id && u32(frames[1].payload,4) == 3,"selected_identity_wrong");
    const auto& profile = frames[2].payload;
    preserved(profile,config.profile_template,{{0,4},{8,8},{24,12},{40,4},{52,8},{72,68}});
    for (const auto& [offset,field] : std::initializer_list<std::pair<std::size_t,const char*>>{
             {0,"role_id"},{24,"wins"},{28,"losses"},{32,"draws"},{40,"model"},{52,"level"},{56,"vip_level"},
             {72,"purchase_score"},{100,"experience"},{104,"escapes"}})
        require(u32(profile,offset) == account.at(field).get<std::uint32_t>(),"profile_field_offset_wrong");
    require(u32(profile,8) == 3 && u32(profile,12) == 0xffffffffU,"profile_room_game_wrong");
    require(f64(profile,76) == account.at("coins").get<double>() && f64(profile,84) == account.at("gold").get<double>() &&
            f64(profile,92) == account.at("bank").get<double>(),"original_balance_offsets_wrong");
    require(std::equal(name.begin(),name.end(),profile.begin()+108) && profile[108+name.size()] == 0,"profile_gbk_name_wrong");
    require(u32(frames[3].payload,0) == 32 && u32(frames[3].payload,4) == 2,"inventory_policy_wrong");
    require(frames[4].payload == id_bytes(0) && frames[5].payload == id_bytes(0),"empty_lists_wrong");
    require(frames[6].payload == config.bank_template && frames[7].payload == config.stage_progress &&
            frames[8].payload == Bytes({'4','1','1','0',0}) && frames[9].payload == config.completion_template,"opaque_policy_or_preferences_wrong");
    rejects([&] { callbacks.authenticated_request(login,{34,id_bytes(id)}); },"original_lobby_duplicate_selection");
    rejects([&] { callbacks.authenticated_request(login,{42,Bytes(24)}); },"original_exchange_options_not_configured");
    for (const auto type : {61U,62U})
        for (const auto size : {0U,7U,9U})
            rejects([&] { callbacks.authenticated_request(login,{type,Bytes(size)}); },"original_bank_amount_length_invalid");
    require(callbacks.authenticated_request(login,{105,{'1','2',0}}).empty(),"preferences_sent_unexpected_response");
    require(storage.preferences_for_username(username) == "12","preferences_not_persisted");
    auto reconnect = make_original_lobby_callbacks(storage,config);
    require(reconnect.verify_credentials(username,password),"reconnect_authentication_failed");
    static_cast<void>(reconnect.login_responses(login));
    const auto restored = reconnect.authenticated_request(login,{34,id_bytes(id)});
    require(restored[8].payload == Bytes({'1','4',0}),"saved_preferences_or_tutorial_mask_wrong");
    require(storage.preferences_for_username(username) == "12","tutorial_mask_persisted_unrequested");
}
void explicit_templates_required() {
    auto config = policy();
    validate_original_lobby_policy(config);
    config.room_template.clear();
    rejects([&] { validate_original_lobby_policy(config); },"original_policy_template_length_invalid");
    config = policy(); config.provenance.clear();
    rejects([&] { validate_original_lobby_policy(config); },"original_policy_provenance_required");
    config = policy(); config.stage_progress = {1,0,2,0};
    rejects([&] { validate_original_lobby_policy(config); },"original_policy_progress_invalid");
    config = policy(); config.room_id = 32767;
    rejects([&] { validate_original_lobby_policy(config); },"original_policy_room_invalid");
    for (const auto offset : {8U,16U,24U}) {
        config = policy();
        std::fill_n(config.bank_template.begin()+offset,8,0xff);
        rejects([&] { validate_original_lobby_policy(config); },"original_bank_limits_invalid");
    }
}
void user_slot_capacity_is_an_id_bound(Storage& storage,const Json& first,const Json& second) {
    auto config = policy(); config.player_capacity = 2;
    const auto password = client_text("\xe5\xaf\x86\xe7\xa0\x81",ClientProfile::original);
    auto safe = make_original_lobby_callbacks(storage,config);
    const auto first_name = first.at("username").get<std::string>();
    require(safe.verify_credentials(first_name,password),"capacity_fixture_login_failed");
    require(safe.login_responses({first_name,0}).size() == 2,"in_range_id_rejected");
    auto overflow = make_original_lobby_callbacks(storage,config);
    const auto second_name = second.at("username").get<std::string>();
    require(overflow.verify_credentials(second_name,password),"capacity_fixture_login_failed");
    rejects([&] { overflow.login_responses({second_name,0}); },"original_lobby_user_slot_out_of_range");
}
void encoded_session_uses_original_packets(Storage& storage,const Json& account) {
    const auto username = account.at("username").get<std::string>();
    const auto role_id = account.at("role_id").get<std::uint32_t>();
    RichLobbySession session({"127.0.0.1",0,local_lobby_handshake(),ClientVersion::legacy},
                             make_original_lobby_callbacks(storage,policy()));
    static_cast<void>(session.start());
    auto input = encode_frame({759,id_bytes(113)},{Channel::lobby_c2s,std::nullopt,ClientVersion::legacy});
    Bytes login;
    append_le(login,0x12345678,4); append_le(login,132,4); append_le(login,0,4);
    login.resize(144,0xca);
    const auto name = client_text(username,ClientProfile::original);
    const auto password = client_text("\xe5\xaf\x86\xe7\xa0\x81",ClientProfile::original);
    std::copy(name.begin(),name.end(),login.begin()+12); login[12+name.size()] = 0;
    std::copy(password.begin(),password.end(),login.begin()+76); login[76+password.size()] = 0;
    for (const auto& request : std::vector<Frame>{{58,login},{34,id_bytes(role_id)}}) {
        const auto packet = encode_frame(request,{Channel::lobby_c2s,219,ClientVersion::legacy});
        input.insert(input.end(),packet.begin(),packet.end());
    }
    const auto output = session.feed(input);
    const std::uint32_t types[]{67,1,3,9,7,140,4,2,100,103,106,30};
    require(output.size() == std::size(types),"encoded_session_response_count_wrong");
    for (std::size_t i = 0; i < output.size(); ++i) {
        const auto frame = decode_frame(output[i],{Channel::lobby_s2c,219,ClientVersion::legacy});
        require(frame.wire_type == types[i],"encoded_session_response_type_wrong");
        if (frame.wire_type == 3) require(frame.payload.size() == 220,"encoded_original_room_size_wrong");
        if (frame.wire_type == 7) require(frame.payload.size() == 268 && u32(frame.payload,0) == role_id,"encoded_original_profile_wrong");
    }
    session.finish();
}
Json create_account(Storage& storage,const char* username,int seed) {
    auto role = storage.dispatch("accounts.create",{{"username",username},{"password","\xe5\xaf\x86\xe7\xa0\x81"}}).at("account");
    Json changes{{"coins",seed+0.25},{"gold",seed+0.5},{"bank",seed+0.75},{"wins",seed},{"losses",seed+1},
                 {"draws",seed+2},{"escapes",seed+3},{"purchase_score",seed+4}};
    Json expected = Json::object();
    for (const auto& [key,value] : changes.items()) { static_cast<void>(value); expected[key] = role.at(key); }
    return storage.dispatch("accounts.update",{{"role_id",role.at("role_id")},{"expected",expected},{"changes",changes},{"reason","isolated adapter test"}}).at("account");
}
}
int main() {
    try {
        explicit_templates_required();
        const auto path = scratch();
        Storage storage(path/L"original.sqlite3",ClientProfile::original);
        const auto first = create_account(storage,"\xe6\xb5\x8b\xe8\xaf\x95",10);
        const auto second = create_account(storage,"Second",20);
        require(first.at("role_id") != second.at("role_id"),"fixture_ids_equal");
        exact_packets_and_database_ownership(storage,first,second);
        exact_packets_and_database_ownership(storage,second,first);
        user_slot_capacity_is_an_id_bound(storage,first,second);
        encoded_session_uses_original_packets(storage,first);
        Storage wrong_profile(path/L"richonline.sqlite3");
        rejects([&] { make_original_lobby_callbacks(wrong_profile,policy()); },"original_lobby_storage_profile_required");
        std::cout << "original lobby adapter tests PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
