#include "server_lobby_adapter.hpp"
#include "richonline_team_identity.hpp"
#include "richonline_account_services.hpp"
#include "richonline_mail_service.hpp"
#include "credentials.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <chrono>
#include <cmath>
#include <fstream>
#include <limits>
#include <utility>

namespace richnet {
namespace {
using Json = nlohmann::json;
std::int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
std::uint32_t integer(const Json& value) {
    if (!value.is_number_integer() || value < 0 || value > std::numeric_limits<std::int32_t>::max())
        throw CodecError("lobby_role_integer_out_of_range");
    return value.get<std::uint32_t>();
}
double balance(const Json& value) {
    if (!value.is_number()) throw CodecError("lobby_role_balance_invalid");
    const auto result = value.get<double>();
    if (!std::isfinite(result) || result < 0) throw CodecError("lobby_role_balance_invalid");
    return result;
}
LobbyRole parse_role(const Json& record) {
    LobbyRole role{integer(record.at("role_id")), integer(record.at("model")), integer(record.at("purchase_score")),
        integer(record.at("level")), integer(record.at("wins")), integer(record.at("losses")), integer(record.at("draws")),
        integer(record.at("experience")), integer(record.at("vip_level")), integer(record.at("escapes")),
        balance(record.at("coins")), balance(record.at("gold")), balance(record.at("bank")), client_text(record.at("name").get<std::string>())};
    if (role.id == 0 || role.model > 8 || role.level > 20 || role.vip_level > 3 || role.name.size() >= 32)
        throw CodecError("lobby_role_field_out_of_range");
    return role;
}
void put_u32(Bytes& data, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) data.at(offset + i) = static_cast<std::uint8_t>(value >> (i * 8));
}
void put_double(Bytes& data, std::size_t offset, double value) {
    const auto bits = std::bit_cast<std::uint64_t>(value);
    for (std::size_t i = 0; i < 8; ++i) data.at(offset + i) = static_cast<std::uint8_t>(bits >> (i * 8));
}
double read_double(View data) {
    std::uint64_t bits = 0;
    for (std::size_t i = 0; i < 8; ++i) bits |= static_cast<std::uint64_t>(data[i]) << (i * 8);
    return std::bit_cast<double>(bits);
}
void put_name(Bytes& data, std::size_t offset, View name) {
    std::fill_n(data.begin() + static_cast<std::ptrdiff_t>(offset), 32, 0);
    std::copy(name.begin(), name.end(), data.begin() + static_cast<std::ptrdiff_t>(offset));
}
template<std::size_t Size> Bytes bytes(const std::array<std::uint8_t, Size>& data) { return {data.begin(), data.end()}; }
template<std::size_t Size> std::array<std::uint8_t, Size> opaque(const Json& value) {
    const auto text = value.get<std::string>();
    if (text.size() != Size * 2) throw CodecError("bootstrap_opaque_length_invalid");
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
        throw CodecError("bootstrap_opaque_hex_invalid");
    };
    std::array<std::uint8_t, Size> data{};
    for (std::size_t i = 0; i < Size; ++i)
        data[i] = static_cast<std::uint8_t>((nibble(text[i * 2]) << 4) | nibble(text[i * 2 + 1]));
    return data;
}
RichonlineMailActorCompatibility mail_actor_compatibility(const Json& value) {
    const auto& word=value.at("opaque_word");const auto& small=value.at("opaque_short");
    if(!word.is_number_integer()||word<0||word>std::numeric_limits<std::uint32_t>::max()||
        !small.is_number_integer()||small<std::numeric_limits<std::int16_t>::min()||small>std::numeric_limits<std::int16_t>::max())
        throw CodecError("bootstrap_mail_actor_compatibility_invalid");
    return {word.get<std::uint32_t>(),small.get<std::int16_t>(),opaque<2>(value.at("opaque_padding_hex"))};
}
RichonlineMallCompatibilityPolicy mall_compatibility(const Json& value) {
    const auto& first=value.at("ignored_word0");const auto& last=value.at("ignored_word2");
    const auto& refused=value.at("refused");
    if(!first.is_number_integer()||first<0||first>std::numeric_limits<std::uint32_t>::max()||
        !last.is_number_integer()||last<0||last>std::numeric_limits<std::uint32_t>::max()||
        !refused.is_number_integer()||refused<std::numeric_limits<std::int32_t>::min()||refused>=0)
        throw CodecError("bootstrap_mall_compatibility_integer_invalid");
    const auto version=value.at("inventory_date_version").get<std::string>();
    const auto date=version=="original_2005"?RichonlineInventoryDateVersion::original_2005:
        version=="compat_2021_v1"?RichonlineInventoryDateVersion::compat_2021_v1:
        throw CodecError("bootstrap_mall_date_version_invalid");
    return {first.get<std::uint32_t>(),last.get<std::uint32_t>(),refused.get<std::int32_t>(),
        value.at("evidence").get<std::string>(),date,value.at("verified_client_compatibility_id").get<std::string>()};
}
Bytes parse_progress(const Json& value) {
    if (!value.is_array()) throw CodecError("bootstrap_stage_progress_array_required");
    Bytes progress;
    for (const auto& item : value) {
        const auto parsed = integer(item);
        if (parsed > 255) throw CodecError("bootstrap_stage_progress_byte_invalid");
        progress.push_back(static_cast<std::uint8_t>(parsed));
    }
    return progress;
}
Bytes role_record(const LobbyRole& role, const BootstrapBlobs& blobs, const LobbyInventory& inventory) {
    auto data = bytes(blobs.unknown_role_record);
    put_u32(data, 0, role.id); put_u32(data, 4, role.model); put_u32(data, 8, role.purchase_score);
    put_u32(data, 12, role.level); put_u32(data, 16, role.wins); put_u32(data, 20, role.losses);
    put_u32(data, 24, role.draws); put_u32(data, 32, role.escapes);
    put_double(data, 36, role.gold); put_u32(data, 44, role.experience);
    put_name(data, 48, role.name);
    for (std::size_t i=0;i<inventory.equipment.size();++i) put_u32(data,80+4*i,inventory.equipment[i]);
    return data;
}
Bytes profile_record(const LobbyRole& role, const BootstrapBlobs& blobs, const LobbyInventory& inventory) {
    auto data = bytes(blobs.unknown_profile_record);
    put_u32(data, 0, role.id); put_u32(data, 8, 0); put_u32(data, 12, 0xffffffffU);
    put_u32(data, 24, role.wins); put_u32(data, 28, role.losses); put_u32(data, 32, role.draws);
    put_u32(data, 44, static_cast<std::uint32_t>(richonline_unassigned_player_team));
    put_u32(data, 40, role.model); put_u32(data, 52, role.level); put_u32(data, 56, role.vip_level);
    put_u32(data, 72, 0); put_u32(data, 76, role.purchase_score);
    put_double(data, 80, role.coins); put_double(data, 88, role.gold); put_double(data, 96, role.bank);
    put_u32(data, 104, role.experience); put_u32(data, 108, role.escapes); put_name(data, 112, role.name);
    for (std::size_t i=0;i<inventory.equipment.size();++i) put_u32(data,144+4*i,inventory.equipment[i]);
    return data;
}
Bytes inventory_record(const LobbyInventory& inventory) {
    if (inventory.items.size()>4096) throw CodecError("lobby_inventory_wire_capacity_exceeded");
    Bytes data;
    append_le(data,static_cast<std::uint32_t>(inventory.items.size()),4);
    for (const auto item:inventory.items) {
        append_le(data,item,4);
        // NEW 87FD30 wire 2 consumes but ignores this DWORD; native item count is forced to 1.
        constexpr std::uint32_t ignored_inventory_word=0;
        append_le(data,ignored_inventory_word,4);
    }
    return data;
}
void log_frames(const ControlLog& log, const std::string& event, const std::vector<Frame>& frames) {
    if (!log) return;
    auto lengths = Json::array();
    for (const auto& frame : frames) lengths.push_back({{"wire_type", frame.wire_type}, {"payload_bytes", frame.payload.size()}});
    log(event, {{"frames", lengths}});
}
}

LobbyRole parse_lobby_role(const nlohmann::json& record) { return parse_role(record); }
Bytes encode_lobby_role_record(const LobbyRole& role,const BootstrapBlobs& blobs,const LobbyInventory& inventory) {
    return role_record(role,blobs,inventory);
}

void validate_bootstrap_blobs(const BootstrapBlobs& blobs) {
    if (blobs.provenance.size() < 8) throw CodecError("bootstrap_provenance_required");
    if(blobs.richonline_mail_policy&&blobs.richonline_mail_policy->provenance.size()<8)
        throw CodecError("bootstrap_mail_policy_provenance_required");
    if(blobs.richonline_mall_policy) {
        const auto& policy=*blobs.richonline_mall_policy;
        if(policy.evidence.size()<8||policy.evidence.size()>1024||policy.evidence.find('\0')!=std::string::npos||policy.refused>=0)
            throw CodecError("bootstrap_mall_policy_invalid");
        if((policy.date_version==RichonlineInventoryDateVersion::original_2005&&!policy.verified_client_compatibility_id.empty())||
            (policy.date_version==RichonlineInventoryDateVersion::compat_2021_v1&&policy.verified_client_compatibility_id!=richonline_inventory_compatibility_id)||
            (policy.date_version!=RichonlineInventoryDateVersion::original_2005&&policy.date_version!=RichonlineInventoryDateVersion::compat_2021_v1))
            throw CodecError("bootstrap_mall_date_compatibility_invalid");
    }
    if (blobs.game_capacity == 0 || blobs.game_capacity > 32767 || blobs.player_capacity < 2 || blobs.player_capacity > 32767)
        throw CodecError("bootstrap_channel_capacity_invalid");
    const auto divisor = read_double(View(blobs.unknown_completion).subspan(20, 8));
    if (!std::isfinite(divisor) || divisor <= 0) throw CodecError("bootstrap_exchange_divisor_must_be_finite_positive");
    for (std::size_t i = 4; i < 28; i += 8)
        if (!std::isfinite(read_double(View(blobs.unknown_completion).subspan(i, 8)))) throw CodecError("bootstrap_completion_value_invalid");
    for (std::size_t i = 0; i < 32; i += 8)
        if (!std::isfinite(read_double(View(blobs.unknown_bank_config).subspan(i, 8)))) throw CodecError("bootstrap_bank_value_invalid");
    if (blobs.stage_progress.empty() || blobs.stage_progress.size() > 4096 || blobs.stage_progress.back() != 0 ||
        std::find(blobs.stage_progress.begin(), blobs.stage_progress.end() - 1, 0) != blobs.stage_progress.end() - 1)
        throw CodecError("bootstrap_stage_progress_cstring_invalid");
    if (blobs.setting_text.empty() || blobs.setting_text.size() >= 64 ||
        std::any_of(blobs.setting_text.begin(), blobs.setting_text.end(), [](char c) { return c < '0' || c > '9'; }))
        throw CodecError("bootstrap_setting_text_invalid");
    std::uint32_t settings = 0;
    const auto conversion = std::from_chars(blobs.setting_text.data(), blobs.setting_text.data() + blobs.setting_text.size(), settings);
    if (conversion.ec != std::errc{} || settings > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("bootstrap_setting_text_out_of_range");
    if (std::any_of(blobs.unknown_role_record.begin() + 80, blobs.unknown_role_record.end(), [](std::uint8_t b) { return b != 0; }) ||
        std::any_of(blobs.unknown_profile_record.begin() + 144, blobs.unknown_profile_record.end(), [](std::uint8_t b) { return b != 0; }))
        throw CodecError("bootstrap_inventory_requires_explicit_empty_slots");
    if (blobs.channels.size() > 32767) throw CodecError("bootstrap_channel_catalog_too_large");
    for (std::size_t index=0; index<blobs.channels.size(); ++index) {
        const auto& channel=blobs.channels[index];
        if (channel.key!=index) throw CodecError("bootstrap_channel_keys_must_be_dense");
        if (channel.name_utf8.empty() || channel.name_utf8.find_first_of("\r\n=")!=std::string::npos ||
            channel.name_utf8.find('\0')!=std::string::npos) throw CodecError("bootstrap_channel_name_invalid");
        if (channel.room_capacity==0 || channel.room_capacity>32767 || channel.player_capacity<2 || channel.player_capacity>32767)
            throw CodecError("bootstrap_channel_capacity_invalid");
        if (channel.lobby_type>3 || channel.status>1 || channel.min_level>channel.max_level ||
            !std::isfinite(channel.min_gold) || !std::isfinite(channel.max_gold) || channel.min_gold<0 || channel.min_gold>channel.max_gold)
            throw CodecError("bootstrap_channel_restrictions_invalid");
        if (!std::isfinite(read_double(View(channel.wire_record).subspan(64,8))) ||
            !std::isfinite(read_double(View(channel.wire_record).subspan(72,8)))) throw CodecError("bootstrap_channel_scalar_invalid");
    }
}

BootstrapBlobs load_bootstrap_blobs(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw CodecError("bootstrap_file_open_failed");
    try {
        const auto config = Json::parse(file);
        BootstrapBlobs blobs{config.at("provenance").get<std::string>(),
            opaque<80>(config.at("unknown_channel_record_hex")), opaque<208>(config.at("unknown_role_record_hex")),
            opaque<272>(config.at("unknown_profile_record_hex")), opaque<16>(config.at("unknown_login_result_hex")),
            opaque<16>(config.at("unknown_identity_record_hex")), opaque<4>(config.at("unknown_empty_list_hex")),
            opaque<32>(config.at("unknown_bank_config_hex")), opaque<28>(config.at("unknown_completion_hex")),
            integer(config.at("game_capacity")), integer(config.at("player_capacity")),
            parse_progress(config.at("stage_progress")), config.at("setting_text").get<std::string>(), {}};
        if (config.contains("room_unknown_prefix")) {
            const auto& prefix = config.at("room_unknown_prefix");
            if (!prefix.is_number_integer() || prefix < 0 || prefix > std::numeric_limits<std::uint32_t>::max())
                throw CodecError("bootstrap_room_prefix_out_of_range");
            blobs.room_unknown_prefix = prefix.get<std::uint32_t>();
        }
        blobs.grant_test_rp_certificate=config.value("grant_test_rp_certificate",false);
        if(config.value("unlock_all_boss_maps_for_testing",false)) {
            // NEW6A1660 indexes ordinary stages10..21 and special Zhao stage180.
            // Preserve a nonzero C string prefix; this changes only the lobby UI.
            blobs.stage_progress.resize(std::max<std::size_t>(blobs.stage_progress.size(),182),1);
            std::replace(blobs.stage_progress.begin(),blobs.stage_progress.end()-1,std::uint8_t{0},std::uint8_t{1});
            for(std::size_t index=10;index<=21;++index) blobs.stage_progress[index]=2;
            blobs.stage_progress[180]=2;
            blobs.stage_progress.back()=0;
        }
        if (config.contains("social_server_id")) blobs.social_server_id=integer(config.at("social_server_id"));
        if(config.contains("richonline_mail_policy")) {
            const auto& policy=config.at("richonline_mail_policy");
            blobs.richonline_mail_policy=RichonlineMailBootstrapPolicy{policy.at("provenance").get<std::string>(),
                {mail_actor_compatibility(policy.at("sender_actor")),mail_actor_compatibility(policy.at("recipient_actor"))}};
        }
        if(config.contains("richonline_mall_policy")) blobs.richonline_mall_policy=mall_compatibility(config.at("richonline_mall_policy"));
        if (config.contains("channels")) {
            const auto& channels=config.at("channels");
            if (!channels.is_array() || channels.empty()) throw CodecError("bootstrap_channels_array_required");
            for (const auto& channel:channels)
                blobs.channels.push_back({integer(channel.at("key")),channel.at("name_utf8").get<std::string>(),
                    integer(channel.at("room_capacity")),integer(channel.at("player_capacity")),
                    integer(channel.at("lobby_type")),integer(channel.at("status")),channel.at("min_gold").get<double>(),
                    channel.at("max_gold").get<double>(),integer(channel.at("min_level")),integer(channel.at("max_level")),
                    opaque<80>(channel.at("wire_record_hex"))});
        }
        validate_bootstrap_blobs(blobs);
        return blobs;
    } catch (const Json::exception&) { throw CodecError("bootstrap_json_invalid"); }
}

LobbyOptions ServerLobbyOptions::transport() const { return {host, port, handshake}; }

ServerLobbyAdapter::ServerLobbyAdapter(Storage& storage, BootstrapBlobs blobs, ControlLog log)
    : storage_(storage), blobs_(std::move(blobs)), log_(std::move(log)) {
    validate_bootstrap_blobs(blobs_);
    storage_.require_inventory_date_version(blobs_.richonline_mall_policy?
        blobs_.richonline_mall_policy->date_version:RichonlineInventoryDateVersion::original_2005);
    if (log_) log_("lobby_bootstrap_policy_loaded", {{"provenance", blobs_.provenance},
        {"exchange_divisor", read_double(View(blobs_.unknown_completion).subspan(20, 8))}, {"runtime_client_verified", false}});
    if(log_&&blobs_.richonline_mail_policy) log_("richonline_mail_policy_loaded",{{"provenance",blobs_.richonline_mail_policy->provenance}});
    if(log_&&blobs_.richonline_mall_policy) log_("richonline_mall_policy_loaded",{{"evidence",blobs_.richonline_mall_policy->evidence},
        {"inventory_date_version",static_cast<std::uint16_t>(blobs_.richonline_mall_policy->date_version)},
        {"verified_client_compatibility_id",blobs_.richonline_mall_policy->verified_client_compatibility_id}});
}

Frame ServerLobbyAdapter::profile_refresh(const std::string& username,std::uint32_t selected,const Json& current_role) {
    const auto role=parse_role(current_role);
    if(role.id!=selected) throw CodecError("richonline_mall_profile_identity_mismatch");
    return {7,profile_record(role,blobs_,storage_.lobby_inventory(username,selected,unix_now()))};
}

std::vector<Frame> ServerLobbyAdapter::login_responses(const LobbyLogin& login) {
    const auto now=unix_now();
    if (blobs_.grant_test_rp_certificate) {
        const auto grant=storage_.ensure_test_rp_certificate(login.username_utf8,now);
        if (log_) log_("lobby_test_rp_certificate",{{"granted",grant.granted},{"renewed",grant.renewed},
            {"equipped_roles",grant.equipped},{"equipment_conflicts",grant.conflicts}});
    }
    const auto records = storage_.roles_for_username(login.username_utf8);
    if (!records.is_array() || records.empty() || records.size() > 1024) throw CodecError("lobby_account_role_list_invalid");
    Bytes role_list;
    append_le(role_list, static_cast<std::uint32_t>(records.size()), 4);
    for (const auto& record : records) {
        const auto role=parse_role(record);
        const auto encoded = role_record(role, blobs_,storage_.lobby_inventory(login.username_utf8,role.id,now));
        role_list.insert(role_list.end(), encoded.begin(), encoded.end());
    }
    auto result = bytes(blobs_.unknown_login_result);
    put_u32(result, 0, parse_role(records.front()).id);
    put_u32(result, 4, blobs_.channels.empty() ? 1 : static_cast<std::uint32_t>(blobs_.channels.size()));
    std::vector<Frame> frames{{67, std::move(role_list)}, {1, std::move(result)}};
    if (blobs_.channels.empty()) {
        auto channel=bytes(blobs_.unknown_channel_record);
        put_u32(channel,32,0); put_u32(channel,48,blobs_.game_capacity); put_u32(channel,52,blobs_.player_capacity);
        frames.push_back({3,std::move(channel)});
    } else for (const auto& entry:blobs_.channels) {
        auto channel=bytes(entry.wire_record);
        put_u32(channel,32,entry.key); put_u32(channel,48,entry.room_capacity); put_u32(channel,52,entry.player_capacity);
        frames.push_back({3,std::move(channel)});
    }
    log_frames(log_, "lobby_login_catalog_built", frames);
    return frames;
}

std::vector<Frame> ServerLobbyAdapter::authenticated_request(const LobbyLogin& login, const Frame& frame) {
    if (frame.wire_type == 105) {
        // NEW 8A06C0 sends this CString without registering a response callback.
        // Preferences are account-wide and may be saved before role selection.
        try {
            storage_.save_preferences(login.username_utf8, frame.payload);
            if (log_) log_("richonline_preferences_save", {{"wire_type", 105},
                {"payload_bytes", frame.payload.size()}, {"persisted", true}, {"lobby_preserved", true}});
        } catch (const StorageError& error) {
            if (log_) log_("richonline_preferences_save", {{"wire_type", 105},
                {"payload_bytes", frame.payload.size()}, {"persisted", false},
                {"reason", error.what()}, {"lobby_preserved", true}});
        }
        return {};
    }
    if (frame.wire_type != 34) {
        if (log_) log_("lobby_authenticated_request_rejected", {{"wire_type", frame.wire_type},
            {"payload_bytes", frame.payload.size()}, {"reason", "handler_not_implemented"}});
        throw CodecError("lobby_authenticated_request_unsupported");
    }
    if (frame.payload.size() != 4) throw CodecError("lobby_role_selection_length_invalid");
    const auto selected = read_le(frame.payload);
    const auto records = storage_.roles_for_username(login.username_utf8);
    const auto found = std::find_if(records.begin(), records.end(), [&](const Json& role) { return integer(role.at("role_id")) == selected; });
    if (found == records.end()) throw CodecError("lobby_role_not_owned");
    const auto role = parse_role(*found);
    if (blobs_.channels.empty() && role.id >= blobs_.player_capacity) throw CodecError("lobby_role_outside_client_slot_capacity");
    std::vector<Frame> frames{{70, frame.payload}};
    log_frames(log_, "lobby_role_selection_confirmed", frames);
    return frames;
}

std::vector<Frame> ServerLobbyAdapter::account_request(const LobbyLogin& login,std::uint32_t role_id,const Frame& frame) {
    if(auto mail=richonline_mail_request(storage_,login.username_utf8,role_id,frame,unix_now(),{0,-112})) {
        if(log_) log_("richonline_mail_operation",{{"wire_type",frame.wire_type},{"role_id",role_id},{"diagnostic",mail->diagnostic}});
        return std::move(mail->frames);
    }
    const auto policy=richonline_account_policy(blobs_.unknown_bank_config,blobs_.unknown_completion);
    auto result=richonline_account_request(storage_,login.username_utf8,role_id,frame,policy);
    if (!result) throw CodecError("richonline_account_wire_not_routed");
    if (log_) log_("richonline_account_operation",{{"wire_type",frame.wire_type},{"role_id",role_id},
        {"success",result->rejection.empty()},{"reason",result->rejection}});
    return {std::move(result->response)};
}

std::vector<Frame> ServerLobbyAdapter::channel_responses(const LobbyLogin& login, std::uint32_t selected, std::uint32_t channel) {
    const auto records = storage_.roles_for_username(login.username_utf8);
    const auto found = std::find_if(records.begin(), records.end(), [&](const Json& role) { return integer(role.at("role_id")) == selected; });
    if (found == records.end()) throw CodecError("lobby_role_not_owned");
    const auto role = parse_role(*found);
    const auto capacity=blobs_.channels.empty() ? blobs_.player_capacity : blobs_.channels.at(channel).player_capacity;
    if (role.id >= capacity) throw CodecError("lobby_role_outside_client_slot_capacity");
    auto identity = bytes(blobs_.unknown_identity_record);
    put_u32(identity, 0, role.id); put_u32(identity, 4, channel);
    const auto inventory=storage_.lobby_inventory(login.username_utf8,role.id,unix_now());
    const auto preferences = storage_.preferences_for_username(login.username_utf8).value_or(blobs_.setting_text);
    Bytes setting(preferences.begin(), preferences.end()); setting.push_back(0);
    std::vector<Frame> frames{{9, std::move(identity)}, {7, profile_record(role, blobs_,inventory)}, {2, inventory_record(inventory)},
        {100, bytes(blobs_.unknown_bank_config)}, {103, blobs_.stage_progress}, {106, std::move(setting)}, {30, bytes(blobs_.unknown_completion)}};
    auto mail=richonline_mail_snapshot(storage_,login.username_utf8,role.id);
    frames.insert(frames.begin()+3,std::make_move_iterator(mail.begin()),std::make_move_iterator(mail.end()));
    log_frames(log_, "lobby_channel_bootstrap_built", frames);
    return frames;
}
}
