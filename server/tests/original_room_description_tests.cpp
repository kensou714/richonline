#include "original_room_description.hpp"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>

namespace {
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
class FixtureFile final {
public:
    FixtureFile() {
        path = std::filesystem::temp_directory_path() / ("richnet-map-" + std::to_string(std::random_device{}()));
        check(std::filesystem::create_directory(path), "fixture directory collision");
        directory = path;
        path /= "index.json";
    }
    ~FixtureFile() { std::error_code ignored; std::filesystem::remove_all(directory, ignored); }
    void write(std::string_view value) const {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(value.data(), static_cast<std::streamsize>(value.size()));
        check(static_cast<bool>(file), "fixture write failed");
    }
    std::filesystem::path path;
private:
    std::filesystem::path directory;
};
void put32(richnet::Bytes& data, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) data[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}
richnet::Bytes extension(std::string_view name = "bS_1_1") {
    richnet::Bytes data(64, 0xa5);
    std::copy(name.begin(), name.end(), data.begin());
    data[name.size()] = 0;
    constexpr std::array<std::uint8_t, 16> signature{
        0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    std::copy(signature.begin(), signature.end(), data.begin() + 32);
    return data;
}
richnet::Bytes description() {
    richnet::Bytes data(128, 0xab);
    data[0] = 0xd6;
    data[1] = 0xd0;
    data[2] = 0;
    put32(data, 32, 0xababcdefU | 0x40U);
    put32(data, 40, 1);
    put32(data, 44, 4);
    const auto map = extension();
    put32(data, 120, static_cast<std::uint32_t>(map.size()));
    data.insert(data.end(), map.begin(), map.end());
    return data;
}
void test_real_catalog_and_opaque_preservation(const richnet::OriginalMapCatalog& maps) {
    check(maps.validate(extension()) == "BS_1_1.emp", "alias lookup must return canonical map source");
    check(maps.validate(extension("bs_1_1.EMP")) == "BS_1_1.emp", "full source must be case insensitive");
    const auto original = description();
    const auto parsed = richnet::parse_original_game_description(original, maps);
    auto expected = original;
    std::fill(expected.begin() + 124, expected.begin() + 128, std::uint8_t{0});
    check(parsed.wire == expected, "only relocated pointer may change; opaque bytes and GBK room name must survive");
    check(parsed.map_name == "BS_1_1.emp" && parsed.max_players == 4, "parsed known fields differ");
    check(original[124] == 0xab, "parsing mutated caller input");
}
void test_map_extensions(const richnet::OriginalMapCatalog& maps) {
    for (std::size_t size = 0; size < 48; ++size)
        rejects([&] { maps.validate(richnet::Bytes(size)); }, "original_map_extension_missing");
    auto data = extension();
    std::fill(data.begin(), data.begin() + 32, std::uint8_t{'x'});
    rejects([&] { maps.validate(data); }, "original_map_name_invalid");
    data = extension(); data[0] = 0;
    rejects([&] { maps.validate(data); }, "original_map_name_invalid");
    data = extension(); data[0] = 0x80;
    rejects([&] { maps.validate(data); }, "original_map_name_invalid");
    rejects([&] { maps.validate(extension("unknown")); }, "original_map_resource_unknown");
    data = extension(); data[32] ^= 1;
    rejects([&] { maps.validate(data); }, "original_map_signature_mismatch");
    rejects([&] { maps.validate(richnet::Bytes(richnet::max_frame_total)); }, "original_map_extension_size_invalid");
}
void test_description_boundaries(const richnet::OriginalMapCatalog& maps) {
    const auto parse = [&](const richnet::Bytes& data) { return richnet::parse_original_game_description(data, maps); };
    for (std::size_t size = 0; size < 128; ++size)
        rejects([&] { parse(richnet::Bytes(size)); }, "original_game_description_truncated");
    rejects([&] { parse(richnet::Bytes(richnet::max_frame_total)); }, "original_game_description_size_invalid");
    auto data = description(); data.push_back(1);
    rejects([&] { parse(data); }, "original_game_description_length_mismatch");
    data = description(); put32(data, 120, 0xffffffffU);
    rejects([&] { parse(data); }, "original_game_description_length_mismatch");
    data = description(); data[32] &= 0xbf;
    rejects([&] { parse(data); }, "original_game_extension_flag_missing");
    data = description(); data[0] = 0;
    rejects([&] { parse(data); }, "original_game_name_invalid");
    data = description(); std::fill(data.begin(), data.begin() + 32, std::uint8_t{0xab});
    rejects([&] { parse(data); }, "original_game_name_invalid");
    for (const auto capacity : {std::array{0U,1U}, std::array{2U,1U}, std::array{1U,5U}, std::array{1U,0xffffffffU}}) {
        data = description(); put32(data, 40, capacity[0]); put32(data, 44, capacity[1]);
        rejects([&] { parse(data); }, "original_game_player_capacity_invalid");
    }
    for (const auto maximum : {1U, 4U}) {
        data = description(); put32(data, 40, maximum); put32(data, 44, maximum);
        check(parse(data).max_players == maximum, "valid capacity boundary rejected");
    }
    data = description(); data.resize(richnet::max_frame_total - 16U, 0xa5);
    put32(data, 120, static_cast<std::uint32_t>(data.size() - 128));
    check(parse(data).wire.size() == data.size(), "maximum framed description must fit");
    data.push_back(1);
    rejects([&] { parse(data); }, "original_game_description_size_invalid");
}
void test_index_rejections() {
    FixtureFile file;
    const auto load = [&] { return richnet::OriginalMapCatalog::load(file.path); };
    rejects(load, "original_map_index_open_failed");
    file.write(""); rejects(load, "original_map_index_size_invalid");
    file.write(std::string(1024U * 1024U + 1U, ' ')); rejects(load, "original_map_index_size_invalid");
    for (const auto json : {"[", "null trailing", "[{},]"}) {
        file.write(json); rejects(load, "original_map_index_json_invalid");
    }
    for (const auto json : {"null", "{}", "[]", "0"}) {
        file.write(json); rejects(load, "original_map_index_records_invalid");
    }
    for (const auto json : {"[{}]", "[null]", R"([{"source":1,"signature_hex":"00"}])"}) {
        file.write(json); rejects(load, "original_map_index_record_invalid");
    }
    constexpr std::string_view record = R"({"source":"BS_1_1.emp","signature_hex":"772a81a78767855215578ecff39c3abe"})";
    file.write("[" + std::string(record) + "," + std::string(record) + "]");
    rejects(load, "original_map_index_duplicate");
    file.write(R"([{"source":"a.emp","signature_hex":"00000000000000000000000000000000"},{"source":"A.EMP","signature_hex":"00000000000000000000000000000000"}])");
    rejects(load, "original_map_index_duplicate");
    file.write(R"([{"source":"a.emp","signature_hex":"00000000000000000000000000000000"},{"source":"a.emp.emp","signature_hex":"00000000000000000000000000000000"}])");
    rejects(load, "original_map_index_duplicate");
    for (const auto source : {"", ".emp", "a.exe", "abcdefghijklmnopqrstuvwxyz012345.emp"}) {
        file.write("[{\"source\":\"" + std::string(source) + "\",\"signature_hex\":\"00000000000000000000000000000000\"}]");
        rejects(load, "original_map_source_invalid");
    }
    for (const auto source : {"a\\u0000.emp", "a\\u0080.emp"}) {
        file.write("[{\"source\":\"" + std::string(source) + "\",\"signature_hex\":\"00000000000000000000000000000000\"}]");
        rejects(load, "original_map_name_invalid");
    }
    for (const auto hex : {"", "00", "gg000000000000000000000000000000", "0000000000000000000000000000000000"}) {
        file.write("[{\"source\":\"a.emp\",\"signature_hex\":\"" + std::string(hex) + "\"}]");
        rejects(load, "original_map_signature_invalid");
    }
    file.write(std::string(32, '[') + "0" + std::string(32, ']'));
    rejects(load, "original_map_index_depth_invalid");
    std::string large = "[";
    for (std::size_t i = 0; i < 4097; ++i) large += (i == 0 ? "null" : ",null");
    file.write(large + "]"); rejects(load, "original_map_index_records_invalid");
}
}

int main() {
    try {
        constexpr std::string_view source_path = __FILE__;
        const auto root = std::filesystem::path(std::u8string(source_path.begin(), source_path.end())).parent_path().parent_path().parent_path();
        const auto maps = richnet::OriginalMapCatalog::load(root / "protocol-analysis" / "board-startup" / "maps" / "index.json");
        test_real_catalog_and_opaque_preservation(maps);
        test_map_extensions(maps);
        test_description_boundaries(maps);
        test_index_rejections();
        std::cout << "PASS original real map catalog, aliases/signatures, opaque description preservation and malformed boundaries.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
