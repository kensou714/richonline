#include "original_boss_config.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <iostream>

namespace {
using Json = nlohmann::json;
using richnet::OriginalBossConfig;
// Enabled CARD records in original protocol-analysis/boss-combat/Prop.txt.
const std::set<std::int16_t> known_cards{1038, 1044, 1046, 1063, 1075};
void check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
void rejects(const std::function<void()>& action, std::string_view code) {
    try { action(); } catch (const richnet::CodecError& error) {
        check(error.what() == code, std::string("unexpected rejection: ") + error.what());
        return;
    }
    throw std::runtime_error("expected rejection missing");
}
Json fixture() {
    return Json::parse(R"({"stages":[{
        "stage_id":"BS_1_2","map_name":"BS_1_2.emp","name":"independent fixture",
        "enabled":true,"support_status":"implemented",
        "human_cash":11,"human_deposit":22,"boss_cash":33,"boss_deposit":44,
        "human_tickets":55,"boss_tickets":66,"human_initial_cards":[1044,1038,1044],
        "max_building_skills":5,"boss_attack_attempts":7,"boss_idle_weight":50,
        "boss_mine_weight":20,"boss_weapon_weight":30,"boss_weapon_pool":[1075,1046]
    }]})");
}
OriginalBossConfig parse(const Json& value) { return OriginalBossConfig::parse(value.dump(), known_cards); }
void test_values_are_preserved() {
    const auto parsed = parse(fixture());
    const auto values = parsed.playable("BS_1_2");
    check(values.human.cash == 11 && values.human.deposit == 22 && values.human.tickets == 55,
        "human balances must remain distinct");
    check(values.boss.cash == 33 && values.boss.deposit == 44 && values.boss.tickets == 66,
        "boss balances must remain distinct");
    check(values.human_initial_cards == std::vector<std::int16_t>({1044, 1038, 1044}),
        "initial card order and duplicates are intentional inventory");
    check(values.max_building_skills == 5 && values.attack.attempts == 7 && values.attack.idle_weight == 50 &&
        values.attack.mine_weight == 20 && values.attack.weapon_weight == 30 &&
        values.attack.weapon_pool == std::vector<std::int16_t>({1075, 1046}), "attack policy must preserve explicit values");
    const auto& meta = parsed.stages().at("BS_1_2");
    check(meta.map_name == "BS_1_2.emp" && meta.name == "independent fixture" && meta.enabled &&
        meta.support_status == richnet::OriginalBossSupport::implemented, "stage metadata changed");
    rejects([&] { parsed.playable("BS_1_9"); }, "original_boss_stage_unknown");
}
void test_schema_and_types() {
    for (const auto& invalid : {Json(), Json::array(), Json::object(), Json{{"stages", Json::array()}},
        Json{{"stages", 7}}, Json{{"stages", Json::array()}, {"extra", 1}}})
        rejects([&] { parse(invalid); }, "original_boss_document_invalid");
    const auto original = fixture();
    for (const auto& [key, value] : original.at("stages").at(0).items()) {
        static_cast<void>(value);
        auto missing = original; missing["stages"][0].erase(key);
        rejects([&] { parse(missing); }, "original_boss_stage_fields_invalid");
    }
    auto extra = fixture(); extra["stages"][0]["unknown"] = 0;
    rejects([&] { parse(extra); }, "original_boss_stage_fields_invalid");
    auto duplicate = fixture(); duplicate["stages"].push_back(duplicate["stages"][0]);
    rejects([&] { parse(duplicate); }, "original_boss_stage_duplicate");
    for (const auto& enabled : {Json(1), Json("true"), Json()}) {
        auto bad = fixture(); bad["stages"][0]["enabled"] = enabled;
        rejects([&] { parse(bad); }, "original_boss_enabled_invalid");
    }
    for (const auto key : {"human_cash", "human_deposit", "boss_cash", "boss_deposit", "human_tickets", "boss_tickets",
        "max_building_skills", "boss_attack_attempts", "boss_idle_weight", "boss_mine_weight", "boss_weapon_weight"}) {
        for (const auto& value : {Json(-1), Json(1.0), Json(true), Json("1"), Json(4294967296ULL)}) {
            auto bad = fixture(); bad["stages"][0][key] = value;
            rejects([&] { parse(bad); }, "original_boss_number_invalid");
        }
    }
    for (const auto key : {"stage_id", "map_name", "name", "support_status"}) {
        for (const auto& value : {Json(0), Json(""), Json("\n"), Json(std::string(257, 'a'))}) {
            auto bad = fixture(); bad["stages"][0][key] = value;
            rejects([&] { parse(bad); }, "original_boss_text_invalid");
        }
    }
}
void test_boundaries_and_cards() {
    for (const auto key : {"human_cash", "human_deposit", "boss_cash", "boss_deposit", "human_tickets", "boss_tickets"}) {
        auto bound = fixture(); bound["stages"][0][key] = 2147483647U; parse(bound);
        bound["stages"][0][key] = 2147483648U;
        rejects([&] { parse(bound); }, "original_boss_number_invalid");
        bound["stages"][0][key] = 0; parse(bound);
        bound["stages"][0][key] = nullptr;
        rejects([&] { parse(bound); }, "original_boss_enabled_values_unknown");
    }
    for (const auto& [key, maximum] : {std::pair{"max_building_skills", 7}, {"boss_attack_attempts", 8}}) {
        auto bound = fixture(); bound["stages"][0][key] = maximum; parse(bound);
        bound["stages"][0][key] = 0; parse(bound);
        bound["stages"][0][key] = maximum + 1;
        rejects([&] { parse(bound); }, "original_boss_number_invalid");
    }
    for (const auto key : {"boss_idle_weight", "boss_mine_weight", "boss_weapon_weight"}) {
        auto bad = fixture(); bad["stages"][0][key] = 101;
        rejects([&] { parse(bad); }, "original_boss_number_invalid");
    }
    auto weights = fixture(); weights["stages"][0]["boss_idle_weight"] = 51;
    rejects([&] { parse(weights); }, "original_boss_attack_weights_invalid");
    auto inventory = fixture(); inventory["stages"][0]["human_initial_cards"] = Json::array(); parse(inventory);
    inventory["stages"][0]["human_initial_cards"] = std::vector<int>(8, 1038); parse(inventory);
    inventory["stages"][0]["human_initial_cards"].push_back(1038);
    rejects([&] { parse(inventory); }, "original_boss_cards_invalid");
    for (const auto key : {"human_initial_cards", "boss_weapon_pool"}) {
        auto bad = fixture(); bad["stages"][0][key] = Json::array({32000});
        rejects([&] { parse(bad); }, "original_boss_card_unknown");
        bad["stages"][0][key] = Json::array({32768});
        rejects([&] { parse(bad); }, "original_boss_number_invalid");
        bad["stages"][0][key] = "1038";
        rejects([&] { parse(bad); }, "original_boss_cards_invalid");
    }
    for (const auto& pool : {Json::array(), Json::array({1046, 1046}), Json::array({1044})}) {
        auto bad = fixture(); bad["stages"][0]["boss_weapon_pool"] = pool;
        rejects([&] { parse(bad); }, "original_boss_weapon_pool_invalid");
    }
    rejects([&] { OriginalBossConfig::parse(fixture().dump(), {1038,1044,1046}); }, "original_boss_card_unknown");
}
void test_availability_and_map_identity() {
    auto disabled = fixture(); disabled["stages"][0]["enabled"] = false;
    const auto config = parse(disabled);
    rejects([&] { config.playable("BS_1_2"); }, "original_boss_stage_disabled");
    disabled["stages"][0]["human_cash"] = nullptr;
    check(!parse(disabled).stages().at("BS_1_2").human_cash, "disabled unknown field must retain null");
    disabled["stages"][0]["support_status"] = "map_unsupported";
    disabled["stages"][0]["stage_id"] = "BS_2_1"; disabled["stages"][0]["map_name"] = "BS_2_1.emp";
    parse(disabled);
    disabled["stages"][0]["enabled"] = true;
    rejects([&] { parse(disabled); }, "original_boss_enabled_unsupported");
    disabled["stages"][0]["support_status"] = "implemented";
    rejects([&] { parse(disabled); }, "original_boss_support_unimplemented");
    for (const auto id : {"../BS_1_2", "BS_0_1", "BS_01_2", "BS_1_2.emp", "BS_1_a", "bs_1_2"}) {
        auto bad = fixture(); bad["stages"][0]["stage_id"] = id;
        rejects([&] { parse(bad); }, "original_boss_stage_id_invalid");
    }
    auto bad = fixture(); bad["stages"][0]["map_name"] = "BS_1_3.emp";
    rejects([&] { parse(bad); }, "original_boss_map_mismatch");
    bad = fixture(); bad["stages"][0]["support_status"] = "ready";
    rejects([&] { parse(bad); }, "original_boss_support_invalid");
}
void test_document_limits() {
    rejects([&] { OriginalBossConfig::parse("", known_cards); }, "original_boss_document_size_invalid");
    rejects([&] { OriginalBossConfig::parse(std::string(1024U * 1024U + 1U, ' '), known_cards); }, "original_boss_document_size_invalid");
    rejects([&] { OriginalBossConfig::parse("{", known_cards); }, "original_boss_json_invalid");
    rejects([&] { OriginalBossConfig::parse(R"({"stages":[],"stages":[]})", known_cards); }, "original_boss_json_duplicate_key");
    rejects([&] { OriginalBossConfig::parse(R"({"stages":[{"name":"a","name":"b"}]})", known_cards); }, "original_boss_json_duplicate_key");
    rejects([&] { OriginalBossConfig::parse(std::string(10, '[') + "0" + std::string(10, ']'), known_cards); }, "original_boss_document_depth_invalid");
}
void test_real_config() {
    constexpr std::string_view source_path = __FILE__;
    const auto root = std::filesystem::path(std::u8string(source_path.begin(), source_path.end())).parent_path().parent_path().parent_path();
    const auto config = OriginalBossConfig::load(root / "local-server" / "boss-stages.json", known_cards);
    check(config.stages().size() == 8, "existing configuration stage count differs");
    const std::array expected_human{100000U,15000U,20000U,18000U};
    const std::array expected_boss{100000U,100000U,120000U,150000U};
    for (std::size_t i = 0; i < 4; ++i) {
        const auto values = config.playable("BS_1_" + std::to_string(i + 1));
        check(values.human.cash == expected_human[i] && values.boss.cash == expected_boss[i], "real stage balance migration differs");
        check(values.human_initial_cards == std::vector<std::int16_t>({1038,1044}) && values.max_building_skills == 7 &&
            values.attack.attempts == 4 && values.attack.idle_weight == 80 && values.attack.mine_weight == 10 &&
            values.attack.weapon_weight == 10 && values.attack.weapon_pool == std::vector<std::int16_t>({1046,1063,1075}),
            "real stage explicit policy migration differs");
        rejects([&] { config.playable("BS_2_" + std::to_string(i + 1)); }, "original_boss_stage_disabled");
    }
    rejects([&] { OriginalBossConfig::load(root / "local-server" / "missing-boss-stages-fixture.json", known_cards); }, "original_boss_open_failed");
}
}
int main() {
    try {
        test_values_are_preserved(); test_schema_and_types(); test_boundaries_and_cards();
        test_availability_and_map_identity(); test_document_limits(); test_real_config();
        std::cout << "PASS original BOSS explicit configuration, existing stage migration and malformed boundaries.\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
