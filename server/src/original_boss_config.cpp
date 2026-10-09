#include "original_boss_config.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>

namespace richnet {
namespace {
using Json = nlohmann::json;
constexpr std::size_t maximum_document_size = 1024U * 1024U;
constexpr std::array<std::string_view, 18> stage_fields{
    "stage_id", "map_name", "name", "enabled", "support_status",
    "human_cash", "human_deposit", "boss_cash", "boss_deposit", "human_tickets", "boss_tickets",
    "human_initial_cards", "max_building_skills", "boss_attack_attempts", "boss_idle_weight",
    "boss_mine_weight", "boss_weapon_weight", "boss_weapon_pool"};

std::uint32_t number(const Json& value, std::uint32_t maximum) {
    if (!value.is_number_integer() || (value.is_number_unsigned() ? value.get<std::uint64_t>() > maximum :
        value.get<std::int64_t>() < 0 || value.get<std::int64_t>() > maximum))
        throw CodecError("original_boss_number_invalid");
    return value.get<std::uint32_t>();
}
std::optional<std::uint32_t> optional_number(const Json& value, std::uint32_t maximum) {
    if (value.is_null()) return std::nullopt;
    return number(value, maximum);
}
std::string text_value(const Json& value) {
    if (!value.is_string()) throw CodecError("original_boss_text_invalid");
    auto text = value.get<std::string>();
    if (text.empty() || text.size() > 256 || std::any_of(text.begin(), text.end(), [](char byte) {
        return static_cast<unsigned char>(byte) < 32U;
    })) throw CodecError("original_boss_text_invalid");
    return text;
}
bool valid_stage_id(std::string_view id) {
    if (!id.starts_with("BS_") || id.size() > 27) return false;
    const auto separator = id.find('_', 3);
    if (separator == std::string_view::npos) return false;
    const auto positive_digits = [](std::string_view part) {
        return !part.empty() && part.front() >= '1' && part.front() <= '9' &&
            std::all_of(part.begin(), part.end(), [](char digit) { return digit >= '0' && digit <= '9'; });
    };
    return positive_digits(id.substr(3, separator - 3)) && positive_digits(id.substr(separator + 1));
}
std::vector<std::int16_t> cards(const Json& value, const std::set<std::int16_t>& known) {
    if (!value.is_array() || value.size() > 8) throw CodecError("original_boss_cards_invalid");
    std::vector<std::int16_t> result;
    for (const auto& entry : value) {
        const auto card = static_cast<std::int16_t>(number(entry, 32767));
        if (!known.contains(card)) throw CodecError("original_boss_card_unknown");
        result.push_back(card);
    }
    return result;
}
OriginalBossAttackPolicy attack(const Json& entry, const std::set<std::int16_t>& known) {
    OriginalBossAttackPolicy result{
        static_cast<std::uint8_t>(number(entry.at("boss_attack_attempts"), 8)),
        static_cast<std::uint8_t>(number(entry.at("boss_idle_weight"), 100)),
        static_cast<std::uint8_t>(number(entry.at("boss_mine_weight"), 100)),
        static_cast<std::uint8_t>(number(entry.at("boss_weapon_weight"), 100)),
        cards(entry.at("boss_weapon_pool"), known)};
    if (result.idle_weight + result.mine_weight + result.weapon_weight != 100)
        throw CodecError("original_boss_attack_weights_invalid");
    const std::set<std::int16_t> unique(result.weapon_pool.begin(), result.weapon_pool.end());
    if (unique.empty() || unique.size() != result.weapon_pool.size() ||
        std::any_of(unique.begin(), unique.end(), [](std::int16_t card) {
            return card != 1046 && card != 1063 && card != 1075;
        })) throw CodecError("original_boss_weapon_pool_invalid");
    return result;
}
bool complete(const OriginalBossStage& stage) {
    return stage.human_cash && stage.human_deposit && stage.boss_cash && stage.boss_deposit &&
        stage.human_tickets && stage.boss_tickets && stage.human_initial_cards && stage.max_building_skills;
}
OriginalBossStage stage(const Json& entry, const std::set<std::int16_t>& known) {
    if (!entry.is_object() || entry.size() != stage_fields.size() ||
        !std::all_of(stage_fields.begin(), stage_fields.end(), [&](auto key) { return entry.contains(key); }))
        throw CodecError("original_boss_stage_fields_invalid");
    OriginalBossStage result;
    result.stage_id = text_value(entry.at("stage_id"));
    if (!valid_stage_id(result.stage_id)) throw CodecError("original_boss_stage_id_invalid");
    result.map_name = text_value(entry.at("map_name"));
    if (result.map_name != result.stage_id + ".emp") throw CodecError("original_boss_map_mismatch");
    result.name = text_value(entry.at("name"));
    if (!entry.at("enabled").is_boolean()) throw CodecError("original_boss_enabled_invalid");
    result.enabled = entry.at("enabled").get<bool>();
    const auto status = text_value(entry.at("support_status"));
    if (status == "implemented") result.support_status = OriginalBossSupport::implemented;
    else if (status == "map_unsupported") result.support_status = OriginalBossSupport::map_unsupported;
    else throw CodecError("original_boss_support_invalid");
    if (result.support_status == OriginalBossSupport::implemented && result.stage_id != "BS_1_1" &&
        result.stage_id != "BS_1_2" && result.stage_id != "BS_1_3" && result.stage_id != "BS_1_4")
        throw CodecError("original_boss_support_unimplemented");
    if (result.enabled && result.support_status != OriginalBossSupport::implemented)
        throw CodecError("original_boss_enabled_unsupported");
    result.human_cash = optional_number(entry.at("human_cash"), 0x7fffffffU);
    result.human_deposit = optional_number(entry.at("human_deposit"), 0x7fffffffU);
    result.boss_cash = optional_number(entry.at("boss_cash"), 0x7fffffffU);
    result.boss_deposit = optional_number(entry.at("boss_deposit"), 0x7fffffffU);
    result.human_tickets = optional_number(entry.at("human_tickets"), 0x7fffffffU);
    result.boss_tickets = optional_number(entry.at("boss_tickets"), 0x7fffffffU);
    if (!entry.at("human_initial_cards").is_null()) result.human_initial_cards = cards(entry.at("human_initial_cards"), known);
    if (!entry.at("max_building_skills").is_null())
        result.max_building_skills = static_cast<std::uint8_t>(number(entry.at("max_building_skills"), 7));
    result.attack = attack(entry, known);
    if (result.enabled && !complete(result)) throw CodecError("original_boss_enabled_values_unknown");
    return result;
}
}

OriginalBossConfig OriginalBossConfig::parse(std::string_view text, const std::set<std::int16_t>& known_card_ids) {
    if (text.empty() || text.size() > maximum_document_size) throw CodecError("original_boss_document_size_invalid");
    try {
        std::vector<std::set<std::string>> keys;
        const auto document = Json::parse(text, [&](int depth, Json::parse_event_t event, Json& value) {
            if (depth > 8) throw CodecError("original_boss_document_depth_invalid");
            if (event == Json::parse_event_t::object_start) keys.emplace_back();
            if (event == Json::parse_event_t::key && !keys.back().insert(value.get<std::string>()).second)
                throw CodecError("original_boss_json_duplicate_key");
            if (event == Json::parse_event_t::object_end) keys.pop_back();
            return true;
        });
        if (!document.is_object() || document.size() != 1 || !document.contains("stages") ||
            !document.at("stages").is_array() || document.at("stages").empty() || document.at("stages").size() > 4096)
            throw CodecError("original_boss_document_invalid");
        OriginalBossConfig result;
        for (const auto& entry : document.at("stages")) {
            auto parsed = stage(entry, known_card_ids);
            const auto id = parsed.stage_id;
            if (!result.stages_.emplace(id, std::move(parsed)).second) throw CodecError("original_boss_stage_duplicate");
        }
        return result;
    } catch (const Json::exception&) {
        throw CodecError("original_boss_json_invalid");
    }
}

OriginalBossConfig OriginalBossConfig::load(const std::filesystem::path& path, const std::set<std::int16_t>& known_card_ids) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw CodecError("original_boss_open_failed");
    const auto size = file.tellg();
    if (size <= 0 || size > static_cast<std::streamoff>(maximum_document_size))
        throw CodecError("original_boss_document_size_invalid");
    std::string text(static_cast<std::size_t>(size), '\0');
    file.seekg(0);
    if (!file.read(text.data(), static_cast<std::streamsize>(text.size())) || file.peek() != std::char_traits<char>::eof())
        throw CodecError("original_boss_read_failed");
    return parse(text, known_card_ids);
}

OriginalBossStageValues OriginalBossConfig::playable(std::string_view stage_id) const {
    const auto found = stages_.find(std::string(stage_id));
    if (found == stages_.end()) throw CodecError("original_boss_stage_unknown");
    const auto& value = found->second;
    if (!value.enabled) throw CodecError("original_boss_stage_disabled");
    if (value.support_status != OriginalBossSupport::implemented) throw CodecError("original_boss_enabled_unsupported");
    if (!complete(value)) throw CodecError("original_boss_enabled_values_unknown");
    return {{*value.human_cash, *value.human_deposit, *value.human_tickets},
        {*value.boss_cash, *value.boss_deposit, *value.boss_tickets}, *value.human_initial_cards,
        *value.max_building_skills, value.attack};
}
}
