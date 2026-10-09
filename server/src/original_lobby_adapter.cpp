#include "original_lobby_adapter.hpp"
#include "original_bank.hpp"
#include "original_exchange.hpp"
#include "original_lobby_records.hpp"
#include "original_rooms.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <memory>
#include <utility>

namespace richnet {
namespace {
using Json = nlohmann::json;
constexpr auto int_max = static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
std::uint32_t integer(const Json& value) {
    if (!value.is_number_integer() || value < 0 || value > int_max)
        throw CodecError("original_role_integer_invalid");
    return value.get<std::uint32_t>();
}
void put_u32(Bytes& data, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) data.at(offset + i) = static_cast<std::uint8_t>(value >> (i * 8));
}
std::uint32_t preferences(std::string_view text) {
    std::uint32_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (text.empty() || text.size() > 10 || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || result > int_max)
        throw CodecError("original_preferences_invalid");
    return result;
}
Bytes integers(std::initializer_list<std::uint32_t> values) {
    Bytes data;
    for (const auto value : values) append_le(data, value, 4);
    return data;
}
struct Session {
    Storage& storage;
    OriginalLobbyPolicy policy;
    std::optional<std::string> username;
    bool catalog_sent = false;
    std::optional<std::uint32_t> selected;
    std::shared_ptr<OriginalRoomDirectory> rooms;
    LobbyLogSink log;

    void require_identity(const LobbyLogin& login) const {
        if (!username || login.username_utf8 != *username) throw CodecError("original_lobby_not_authenticated");
    }
    Json roles() const {
        const auto records = storage.roles_for_username(*username);
        if (!records.is_array() || records.empty() || records.size() > 1024)
            throw CodecError("original_lobby_role_list_invalid");
        for (const auto& record : records) {
            if (integer(record.at("role_id")) == 0 || record.at("username") != *username)
                throw CodecError("original_lobby_role_record_invalid");
            if (integer(record.at("role_id")) >= policy.player_capacity)
                throw CodecError("original_lobby_user_slot_out_of_range");
        }
        return records;
    }
    std::vector<Frame> login(const LobbyLogin& login) {
        require_identity(login);
        if (catalog_sent) throw CodecError("original_lobby_duplicate_catalog");
        const auto records = roles();
        auto catalog = integers({static_cast<std::uint32_t>(records.size())});
        for (const auto& record : records) {
            const auto encoded = original_role_record(record, policy);
            catalog.insert(catalog.end(), encoded.begin(), encoded.end());
        }
        auto result = policy.login_template;
        put_u32(result, 0, integer(records.front().at("role_id"))); put_u32(result, 4, policy.room_id + 1);
        catalog_sent = true;
        return {{67,std::move(catalog)},{1,std::move(result)}};
    }
    std::vector<Frame> request(const LobbyLogin& login, const Frame& frame) {
        require_identity(login);
        if (!catalog_sent) throw CodecError("original_lobby_catalog_required");
        if (frame.wire_type == 42) {
            if (!selected) throw CodecError("original_lobby_selection_required");
            if (!policy.exchange_ratio) throw CodecError("original_exchange_options_not_configured");
            auto result = original_exchange_response(storage,*username,*selected,frame,*policy.exchange_ratio);
            std::vector<Frame> replies{std::move(result.response)};
            if (result.role) replies.push_back({23,rooms->apply_membership(*selected,original_profile_record(*result.role,policy))});
            return replies;
        }
        if (frame.wire_type == 61 || frame.wire_type == 62) {
            if (!selected) throw CodecError("original_lobby_selection_required");
            return {original_bank_response(storage,*username,*selected,frame,original_bank_limits(policy.bank_template))};
        }
        if (frame.wire_type == 105) {
            if (!selected) throw CodecError("original_lobby_selection_required");
            storage.save_preferences(*username,frame.payload);
            return {};
        }
        if (frame.wire_type == 10) {
            if (!selected) throw CodecError("original_lobby_selection_required");
            if (frame.payload.size() != 4 || read_le(frame.payload) > 4 || rooms->ready(*selected)) {
                const auto actual = rooms->profile(*selected);
                if (log) log("original_room_request_rejected request_type=10 reason=invalid_model_or_ready");
                return {{18,integers({*selected,read_le(View(actual).subspan(40,4))})}};
            }
            const auto role = storage.select_model(*username,*selected,read_le(frame.payload));
            rooms->model_changed(*selected,integer(role.at("model")));
            return {};
        }
        if (frame.wire_type == 3 || frame.wire_type == 4 || frame.wire_type == 5 || frame.wire_type == 6 || frame.wire_type == 9 ||
            frame.wire_type == 23 || frame.wire_type == 60) {
            if (!selected) throw CodecError("original_lobby_selection_required");
            try { rooms->request(*selected,frame); }
            catch (const CodecError& error) {
                if (log) log("original_room_request_rejected request_type=" + std::to_string(frame.wire_type) + " reason=" + error.what());
                if (frame.wire_type != 3 && frame.wire_type != 4 && frame.wire_type != 23) throw;
                auto failure = integers({frame.wire_type,0xffffffffU});
                failure.resize(136,0);
                return {{0xffffffffU,std::move(failure)}};
            }
            return {};
        }
        if (frame.wire_type != 34) throw CodecError("original_lobby_request_unsupported");
        if (selected) throw CodecError("original_lobby_duplicate_selection");
        if (frame.payload.size() != 4) throw CodecError("original_lobby_selection_length_invalid");
        const auto id = read_le(frame.payload);
        const auto records = roles();
        const auto found = std::find_if(records.begin(), records.end(), [&](const Json& role) { return integer(role.at("role_id")) == id; });
        if (found == records.end()) throw CodecError("original_lobby_role_not_owned");
        auto room = policy.room_template;
        put_u32(room,32,policy.room_id); put_u32(room,48,policy.game_capacity); put_u32(room,52,policy.player_capacity);
        put_u32(room,124,read_le(View(room).subspan(124,4)) & ~0x40U);
        put_u32(room,212,0); // Fixed 220-byte record has no appended extension bytes.
        put_u32(room,216,0); // The client decoder replaces this serialized pointer slot.
        auto identity = policy.identity_template;
        put_u32(identity,0,id); put_u32(identity,4,policy.room_id);
        const auto saved = storage.preferences_for_username(*username);
        const auto setting = std::to_string(preferences(saved.value_or(policy.setting_text)) | policy.tutorial_dismissal_mask);
        Bytes setting_bytes(setting.begin(),setting.end()); setting_bytes.push_back(0);
        std::vector<Frame> frames{{3,std::move(room)},{9,std::move(identity)},{7,original_profile_record(*found,policy)},
            {140,integers({policy.item_grid_count,policy.item_per_space})},{4,integers({0})},{2,integers({0})},
            {100,policy.bank_template},{103,policy.stage_progress},{106,std::move(setting_bytes)},{30,policy.completion_template}};
        rooms->enter(id,[database = &storage, config = policy, owner = *username, id] {
            for (const auto& record : database->roles_for_username(owner))
                if (integer(record.at("role_id")) == id) return original_profile_record(record,config);
            throw CodecError("original_lobby_role_not_owned");
        });
        selected = id;
        return frames;
    }
};
}

void validate_original_lobby_policy(const OriginalLobbyPolicy& policy) {
    if (policy.provenance.size() < 8) throw CodecError("original_policy_provenance_required");
    for (const auto& [data,size] : std::initializer_list<std::pair<const Bytes*,std::size_t>>{
             {&policy.room_template,220},{&policy.role_template,208},{&policy.profile_template,268},
             {&policy.login_template,16},{&policy.identity_template,16},{&policy.bank_template,32},{&policy.completion_template,28}})
        if (data->size() != size) throw CodecError("original_policy_template_length_invalid");
    static_cast<void>(original_bank_limits(policy.bank_template));
    if (policy.exchange_ratio && *policy.exchange_ratio < 1) throw CodecError("original_exchange_ratio_invalid");
    if (policy.room_id == 0 || policy.room_id > 32766 || policy.game_capacity == 0 || policy.game_capacity > 32767 ||
        policy.player_capacity < 2 || policy.player_capacity > 32767)
        throw CodecError("original_policy_room_invalid");
    if (policy.item_grid_count == 0 || policy.item_grid_count > 65535 || policy.item_per_space == 0 || policy.item_per_space > 65535)
        throw CodecError("original_policy_inventory_invalid");
    if (policy.stage_progress.empty() || policy.stage_progress.size() > 4096 || policy.stage_progress.back() != 0 ||
        std::find(policy.stage_progress.begin(),policy.stage_progress.end()-1,0) != policy.stage_progress.end()-1)
        throw CodecError("original_policy_progress_invalid");
    static_cast<void>(preferences(policy.setting_text));
    if (policy.tutorial_dismissal_mask > int_max) throw CodecError("original_policy_tutorial_mask_invalid");
}

LobbyCallbackFactory make_original_lobby_factory(Storage& original_storage, OriginalLobbyPolicy policy, LobbyLogSink log,
                                                std::shared_ptr<OriginalGameHost> host) {
    if (original_storage.client_profile() != ClientProfile::original) throw CodecError("original_lobby_storage_profile_required");
    validate_original_lobby_policy(policy);
    auto rooms = std::make_shared<OriginalRoomDirectory>(policy.maps,policy.game_capacity,log,std::move(host),policy.room_id);
    return [&original_storage,policy = std::move(policy),rooms,log]() -> LobbyCallbacks {
    auto state = std::make_shared<Session>(Session{original_storage,policy,std::nullopt,false,std::nullopt,rooms,log});
    return {[state](const std::string& username, View password) {
        if (state->username) throw CodecError("original_lobby_duplicate_authentication");
        if (!state->storage.verify_credentials(username,password)) return false;
        state->username = username;
        return true;
    },[state](const LobbyLogin& login) { return state->login(login); },
      [state](const LobbyLogin& login,const Frame& frame) { return state->request(login,frame); },
      [state] { return state->selected ? state->rooms->drain(*state->selected) : std::vector<Frame>{}; },
      [state] { if (state->selected) { state->rooms->disconnect(*state->selected); state->selected.reset(); } }};
    };
}
LobbyCallbacks make_original_lobby_callbacks(Storage& original_storage, OriginalLobbyPolicy policy) {
    return make_original_lobby_factory(original_storage,std::move(policy))();
}
}
