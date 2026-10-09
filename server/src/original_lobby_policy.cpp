#include "original_lobby_adapter.hpp"
#include "original_options.hpp"
#include "original_room_description.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <string_view>

namespace richnet {
namespace {
using Json = nlohmann::json;
constexpr std::array<std::string_view, 19> fields{
    "version", "client_profile", "provenance", "network", "room_template_hex", "role_template_hex",
    "profile_template_hex", "login_template_hex", "identity_template_hex", "bank_template_hex",
    "completion_template_hex", "room_id", "game_capacity", "player_capacity", "item_grid_count",
    "item_per_space", "stage_progress_hex", "setting_text", "tutorial_dismissal_mask"};
std::string text(const Json& value) {
    if (!value.is_string()) throw CodecError("original_policy_string_required");
    return value.get<std::string>();
}
std::uint32_t integer(const Json& value) {
    if (!value.is_number_integer() || value < 0 || value > std::numeric_limits<std::uint32_t>::max())
        throw CodecError("original_policy_integer_invalid");
    return value.get<std::uint32_t>();
}
Bytes hex(const Json& value, std::size_t min_bytes, std::size_t max_bytes) {
    const auto encoded = text(value);
    if (encoded.size() % 2 != 0 || encoded.size() < min_bytes * 2 || encoded.size() > max_bytes * 2)
        throw CodecError("original_policy_hex_length_invalid");
    const auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
        throw CodecError("original_policy_hex_invalid");
    };
    Bytes bytes;
    bytes.reserve(encoded.size() / 2);
    for (std::size_t i = 0; i < encoded.size(); i += 2)
        bytes.push_back(static_cast<std::uint8_t>((nibble(encoded[i]) << 4) | nibble(encoded[i + 1])));
    return bytes;
}
}

OriginalLobbyPolicy load_original_lobby_policy(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw CodecError("original_policy_file_open_failed");
    const auto size = file.tellg();
    if (size <= 0 || size > 65536) throw CodecError("original_policy_file_size_invalid");
    file.seekg(0);
    try {
        const auto config = Json::parse(file);
        if (!config.is_object()) throw CodecError("original_policy_object_required");
        for (const auto& [key, value] : config.items()) {
            static_cast<void>(value);
            if (key != "client_options_path" && key != "map_catalog_path" && std::find(fields.begin(), fields.end(), key) == fields.end())
                throw CodecError("original_policy_unknown_field");
        }
        for (const auto name : fields)
            if (!config.contains(name)) throw CodecError("original_policy_missing_field");
        if (integer(config.at("version")) != 1) throw CodecError("original_policy_version_unsupported");
        if (text(config.at("client_profile")) != "original") throw CodecError("original_policy_profile_mismatch");
        if (!config.at("network").is_object()) throw CodecError("original_policy_network_object_required");
        OriginalLobbyPolicy policy{text(config.at("provenance")),
            hex(config.at("room_template_hex"),220,220), hex(config.at("role_template_hex"),208,208),
            hex(config.at("profile_template_hex"),268,268), hex(config.at("login_template_hex"),16,16),
            hex(config.at("identity_template_hex"),16,16), hex(config.at("bank_template_hex"),32,32),
            hex(config.at("completion_template_hex"),28,28), integer(config.at("room_id")),
            integer(config.at("game_capacity")), integer(config.at("player_capacity")),
            integer(config.at("item_grid_count")), integer(config.at("item_per_space")),
            hex(config.at("stage_progress_hex"),1,4096), text(config.at("setting_text")),
            integer(config.at("tutorial_dismissal_mask"))};
        if (config.contains("client_options_path")) {
            const auto configured_path = text(config.at("client_options_path"));
            if (configured_path.empty() || configured_path.find('\0') != std::string::npos)
                throw CodecError("original_options_path_invalid");
            auto options_path = std::filesystem::path(std::u8string(configured_path.begin(),configured_path.end()));
            if (options_path.is_relative()) options_path = path.parent_path() / options_path;
            policy.exchange_ratio = load_original_exchange_ratio(options_path);
        }
        if (config.contains("map_catalog_path")) {
            const auto configured = text(config.at("map_catalog_path"));
            if (configured.empty() || configured.find('\0') != std::string::npos)
                throw CodecError("original_map_catalog_path_invalid");
            auto catalog_path = std::filesystem::path(std::u8string(configured.begin(),configured.end()));
            if (catalog_path.is_relative()) catalog_path = path.parent_path() / catalog_path;
            policy.maps = std::make_shared<OriginalMapCatalog>(OriginalMapCatalog::load(catalog_path));
        }
        validate_original_lobby_policy(policy);
        return policy;
    } catch (const Json::exception&) { throw CodecError("original_policy_json_invalid"); }
}
}
