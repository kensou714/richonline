#include "original_lobby_adapter.hpp"
#include "original_bank_fixture.hpp"
#include "original_room_description.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <string_view>

namespace {
using namespace richnet;
using Json = nlohmann::json;
void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
template<class Action> void rejects(Action action, std::string_view code) {
    try { action(); } catch (const CodecError& error) {
        if (error.what() != code) throw std::runtime_error(std::string("unexpected_error: ") + error.what());
        return;
    }
    throw std::runtime_error("expected_rejection");
}
std::string hex_pattern(std::size_t size) {
    std::string result;
    for (std::size_t i = 0; i < size; ++i) result += i % 2 == 0 ? "a5" : "F1";
    return result;
}
Json fixture() {
    return {{"version",1},{"client_profile","original"},{"provenance","Synthetic test bytes, not a captured packet."},
        {"network",{{"bind_host","127.0.0.1"},{"lobby_port",0}}},
        {"room_template_hex",hex_pattern(220)},{"role_template_hex",hex_pattern(208)},
        {"profile_template_hex",hex_pattern(268)},{"login_template_hex",hex_pattern(16)},
        {"identity_template_hex",hex_pattern(16)},{"bank_template_hex",original_bank_test::config_hex},
        {"completion_template_hex",hex_pattern(28)},{"room_id",3},{"game_capacity",8},
        {"player_capacity",100},{"item_grid_count",32},{"item_per_space",2},
        {"stage_progress_hex","01020300"},{"setting_text","0000012"},{"tutorial_dismissal_mask",14}};
}
std::filesystem::path scratch() {
    for (std::uint32_t i = 1; i < 10000; ++i) {
        const auto directory = std::filesystem::temp_directory_path() / L"original-lobby-policy-tests" / std::to_wstring(i);
        if (std::filesystem::create_directories(directory)) return directory / L"lobby-bootstrap.json";
    }
    throw std::runtime_error("scratch_exhausted");
}
void write_text(const std::filesystem::path& path, const std::string& contents) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << contents;
    if (!stream) throw std::runtime_error("fixture_write_failed");
}
OriginalLobbyPolicy load(const std::filesystem::path& path, const Json& value) {
    write_text(path,value.dump());
    return load_original_lobby_policy(path);
}
void preserves_input(const std::filesystem::path& path) {
    const auto actual = load(path,fixture());
    const std::pair<const Bytes*,std::size_t> templates[]{
        {&actual.room_template,220},{&actual.role_template,208},{&actual.profile_template,268},
        {&actual.login_template,16},{&actual.identity_template,16},{&actual.completion_template,28}};
    for (const auto& [bytes,size] : templates) {
        require(bytes->size() == size,"template_size_changed");
        for (std::size_t i = 0; i < size; ++i)
            require(bytes->at(i) == (i % 2 == 0 ? 0xa5 : 0xf1),"opaque_template_changed");
    }
    require(actual.room_id == 3 && actual.game_capacity == 8 && actual.player_capacity == 100,"room_policy_changed");
    require(actual.bank_template == Bytes(original_bank_test::config.begin(),original_bank_test::config.end()),"bank_config_changed");
    require(actual.item_grid_count == 32 && actual.item_per_space == 2,"inventory_policy_changed");
    require(actual.stage_progress == Bytes({1,2,3,0}),"progress_changed");
    require(actual.setting_text == "0000012" && actual.tutorial_dismissal_mask == 14,"preferences_changed");
    require(actual.provenance == fixture().at("provenance").get<std::string>(),"provenance_changed");
}
void schema_failures(const std::filesystem::path& path) {
    const auto valid = fixture();
    for (const auto& [key,value] : valid.items()) {
        static_cast<void>(value);
        auto input = fixture(); input.erase(key);
        rejects([&] { load(path,input); },"original_policy_missing_field");
    }
    auto input = fixture(); input["unknown_field"] = 1;
    rejects([&] { load(path,input); },"original_policy_unknown_field");
    input = fixture(); input["version"] = 2;
    rejects([&] { load(path,input); },"original_policy_version_unsupported");
    input = fixture(); input["client_profile"] = "richonline";
    rejects([&] { load(path,input); },"original_policy_profile_mismatch");
    input = fixture(); input["network"] = Json::array();
    rejects([&] { load(path,input); },"original_policy_network_object_required");
    rejects([&] { load(path,Json::array()); },"original_policy_object_required");
    write_text(path,"{");
    rejects([&] { load_original_lobby_policy(path); },"original_policy_json_invalid");
    write_text(path,std::string(65537,' '));
    rejects([&] { load_original_lobby_policy(path); },"original_policy_file_size_invalid");
    rejects([&] { load_original_lobby_policy(path.parent_path()/L"absent.json"); },"original_policy_file_open_failed");
}
void client_option_paths(const std::filesystem::path& path) {
    require(!load(path,fixture()).exchange_ratio,"unconfigured_exchange_has_invented_ratio");
    constexpr std::string_view source = __FILE__;
    const auto root = std::filesystem::path(std::u8string(source.begin(),source.end())).parent_path().parent_path().parent_path();
    const auto original = root / "Data" / "Option.kpd";
    auto input = fixture();
    const auto encoded = original.u8string();
    input["client_options_path"] = std::string(encoded.begin(),encoded.end());
    require(load(path,input).exchange_ratio == 10,"absolute_option_path_ratio_wrong");
    std::filesystem::copy_file(original,path.parent_path()/L"option-copy.kpd");
    input["client_options_path"] = "option-copy.kpd";
    require(load(path,input).exchange_ratio == 10,"relative_option_path_ratio_wrong");
    input["client_options_path"] = "missing.kpd";
    rejects([&] { load(path,input); },"original_options_open_failed");
    for (const auto value : {std::string{},std::string("bad\0path",8)}) {
        input["client_options_path"] = value;
        rejects([&] { load(path,input); },"original_options_path_invalid");
    }
    input["client_options_path"] = 10;
    rejects([&] { load(path,input); },"original_policy_string_required");
    write_text(path.parent_path()/L"invalid.kpd","broken"); input["client_options_path"] = "invalid.kpd";
    rejects([&] { load(path,input); },"original_kpd_header_truncated");
}
void map_catalog_paths(const std::filesystem::path& path) {
    require(!load(path,fixture()).maps,"unconfigured_maps_has_invented_catalog");
    constexpr std::string_view source = __FILE__;
    const auto root = std::filesystem::path(std::u8string(source.begin(),source.end())).parent_path().parent_path().parent_path();
    const auto original = root / "protocol-analysis" / "board-startup" / "maps" / "index.json";
    auto input = fixture();
    const auto encoded = original.u8string();
    input["map_catalog_path"] = std::string(encoded.begin(),encoded.end());
    Bytes extension(48);
    const std::string map = "BS_1_1.emp";
    std::copy(map.begin(),map.end(),extension.begin());
    const Bytes signature{0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    std::copy(signature.begin(),signature.end(),extension.begin()+32);
    const std::shared_ptr<const OriginalMapCatalog> absolute_maps = load(path,input).maps;
    require(absolute_maps->validate(extension) == map,"absolute_map_catalog_wrong");
    const auto relative = std::filesystem::path(L"地图配置") / L"原版地图.json";
    std::filesystem::create_directories((path.parent_path()/relative).parent_path());
    std::filesystem::copy_file(original,path.parent_path()/relative);
    const auto relative_utf8 = relative.u8string();
    input["map_catalog_path"] = std::string(relative_utf8.begin(),relative_utf8.end());
    require(load(path,input).maps->validate(extension) == map,"relative_unicode_map_catalog_wrong");
    input["map_catalog_path"] = "missing-maps.json";
    rejects([&] { load(path,input); },"original_map_index_open_failed");
    for (const auto value : {std::string{},std::string("bad\0path",8)}) {
        input["map_catalog_path"] = value;
        rejects([&] { load(path,input); },"original_map_catalog_path_invalid");
    }
    input["map_catalog_path"] = 10;
    rejects([&] { load(path,input); },"original_policy_string_required");
    input["map_catalog_path"] = "invalid-maps.json";
    write_text(path.parent_path()/L"invalid-maps.json","{");
    rejects([&] { load(path,input); },"original_map_index_json_invalid");
    write_text(path.parent_path()/L"invalid-maps.json","");
    rejects([&] { load(path,input); },"original_map_index_size_invalid");
}
void scalar_and_hex_failures(const std::filesystem::path& path) {
    for (const auto* field : {"version","room_id","game_capacity","player_capacity","item_grid_count","item_per_space","tutorial_dismissal_mask"}) {
        for (const Json& invalid : std::vector<Json>{-1,1.5,true,"3",nullptr,std::uint64_t{4294967296ULL},std::numeric_limits<std::uint64_t>::max()}) {
            auto input = fixture(); input[field] = invalid;
            rejects([&] { load(path,input); },"original_policy_integer_invalid");
        }
    }
    for (const auto* field : {"room_template_hex","role_template_hex","profile_template_hex","login_template_hex",
                              "identity_template_hex","bank_template_hex","completion_template_hex"}) {
        auto input = fixture(); input[field] = "AA";
        rejects([&] { load(path,input); },"original_policy_hex_length_invalid");
        input = fixture(); auto encoded = input[field].get<std::string>(); encoded[0] = 'G'; input[field] = encoded;
        rejects([&] { load(path,input); },"original_policy_hex_invalid");
        input = fixture(); input[field] = false;
        rejects([&] { load(path,input); },"original_policy_string_required");
    }
    auto input = fixture(); input["stage_progress_hex"] = "0";
    rejects([&] { load(path,input); },"original_policy_hex_length_invalid");
    input = fixture(); input["stage_progress_hex"] = "01000200";
    rejects([&] { load(path,input); },"original_policy_progress_invalid");
    input = fixture(); input["stage_progress_hex"] = "0102";
    rejects([&] { load(path,input); },"original_policy_progress_invalid");
    input = fixture(); input["stage_progress_hex"] = hex_pattern(4097);
    rejects([&] { load(path,input); },"original_policy_hex_length_invalid");
    input = fixture(); input["room_id"] = 32767;
    rejects([&] { load(path,input); },"original_policy_room_invalid");
    input = fixture(); input["item_grid_count"] = 65536;
    rejects([&] { load(path,input); },"original_policy_inventory_invalid");
    input = fixture(); input["tutorial_dismissal_mask"] = 2147483648U;
    rejects([&] { load(path,input); },"original_policy_tutorial_mask_invalid");
    input = fixture(); input["setting_text"] = "2147483648";
    rejects([&] { load(path,input); },"original_preferences_invalid");
}
}
int main() {
    try {
        const auto path = scratch();
        preserves_input(path); schema_failures(path); scalar_and_hex_failures(path);
        client_option_paths(path);
        map_catalog_paths(path);
        std::cout << "original lobby policy tests PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
