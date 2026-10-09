#include "original_map_test_support.hpp"
#include <iostream>

namespace {
using namespace map_test;
void actual_maps_match_existing_oracles(const std::filesystem::path& root) {
    std::size_t maps = 0, boss_maps = 0;
    std::string resource_failures;
    for (const auto& file : std::filesystem::directory_iterator(root / "Map")) {
        if (file.path().extension() != ".emp") continue;
        const auto emp = load_original_emp(file.path());
        const auto reference = oracle(root / "protocol-analysis" / "board-startup" / "maps" / (file.path().stem().string() + ".json"));
        const auto tag = file.path().filename().string();
        check(emp.version == reference.at("version") && emp.width == reference.at("width") && emp.height == reference.at("height"), tag + " dimensions/version");
        check(Bytes(emp.signature.begin(), emp.signature.end()) == from_hex(reference.at("signature_hex").get<std::string>()), tag + " signature");
        check(emp.payload.size() == reference.at("decoded_size") && emp.tail_offset == reference.at("tail_offset"), tag + " decoded boundaries");
        for (std::size_t i = 0; i < 2; ++i) {
            check(integer(emp.payload, i * 4) == reference.at("special_xy").at(i), tag + " special coordinate");
            check(integer(emp.payload, 8 + i * 4) == reference.at("background_size").at(i), tag + " background dimension");
        }
        check(integer(emp.payload, emp.terrain_offset + static_cast<std::size_t>(emp.width) * emp.height * 64)
              == reference.at("decor_count"), tag + " decoration count");
        check(reference.at("cells").size() == static_cast<std::size_t>(emp.width) * emp.height, tag + " oracle cell count");
        for (const auto& cell : reference.at("cells")) {
            const auto id = cell.at("id").get<std::size_t>();
            check(cell.at("raw_i32").size() == 16, tag + " terrain record size");
            for (std::size_t i = 0; i < 16; ++i)
                check(integer(emp.payload, emp.terrain_offset + id * 64 + i * 4) == cell.at("raw_i32").at(i), tag + " terrain raw dword");
            const auto raw_type = integer(emp.payload, emp.tile_types_offset + id * 4);
            const auto special_x = reference.at("special_xy").at(0).get<std::int32_t>();
            const auto special_y = reference.at("special_xy").at(1).get<std::int32_t>();
            const auto special_id = static_cast<std::int64_t>(special_y) * emp.width + special_x;
            const auto oracle_type = special_x >= 0 && special_y >= 0 && static_cast<std::int64_t>(id) == special_id ? 7 : raw_type;
            check(oracle_type == cell.at("tile_type"), tag + " tile type id=" + std::to_string(id) +
                  " raw=" + std::to_string(raw_type) + " expected=" + cell.at("tile_type").dump() +
                  " special=" + reference.at("special_xy").dump());
        }
        check(reference.at("properties").size() == static_cast<std::size_t>(emp.width) * emp.height, tag + " property count");
        for (const auto& property : reference.at("properties")) {
            const auto expected = from_hex(property.at("raw_hex").get<std::string>());
            const auto offset = emp.property_offset + property.at("id").get<std::size_t>() * 88;
            check(expected.size() == 88 && std::equal(expected.begin(), expected.end(), emp.payload.begin() + static_cast<std::ptrdiff_t>(offset)), tag + " property raw bytes");
        }
        const auto tail = from_hex(reference.at("tail_hex").get<std::string>());
        check(Bytes(emp.payload.begin() + static_cast<std::ptrdiff_t>(emp.tail_offset), emp.payload.end()) == tail, tag + " full tail bytes");
        try {
            const auto map = original_map_resources(emp, 10);
            const auto road_count = std::count_if(reference.at("cells").begin(), reference.at("cells").end(), [](const auto& cell) {
                return (static_cast<std::uint32_t>(cell.at("raw_i32").at(0).template get<std::int32_t>()) & 255U) != 255;
            });
            check(map.roads.size() == static_cast<std::size_t>(road_count) && !map.edges.empty(), tag + " road graph");
            check(map.human_funds.cash == read_le(View(tail).subspan(104, 4)) &&
                  map.human_funds.deposit == read_le(View(tail).subspan(108, 4)) &&
                  map.human_funds.tickets == read_le(View(tail).subspan(112, 4)) &&
                  map.scale == read_le(View(tail).subspan(116, 4)), tag + " economic fields");
            if (file.path().filename() == "CM_CS_2.emp")
                check(map.scale == 0, "CM_CS_2 raw scale zero must be retained by resource layer");
            for (const auto& property : map.properties) {
                const auto& expected = reference.at("properties").at(static_cast<std::size_t>(property.id));
                check(property.owner == -1 && property.price >= 0 &&
                      property.price == expected.at("raw_base_price").get<std::int32_t>() * 10, tag + " runtime property price");
            }
        } catch (const CodecError& error) {
            resource_failures += tag + " version=" + std::to_string(emp.version) + " scale=" +
                std::to_string(integer(tail, 116)) + " resources: " + error.what() + "\n";
        }
        if (file.path().stem().string().starts_with("BS_1_")) ++boss_maps;
        ++maps;
    }
    check(maps == 61 && boss_maps == 4, "must cover all 61 existing EMP files and all four first-chapter BOSS maps");
    check(resource_failures.empty(), resource_failures);
}
void synthetic_layout_and_directions() {
    const auto raw = fixture();
    const auto decoded = decode_original_emp(encode_fixture(raw));
    check(decoded.payload == raw.payload && decoded.header == raw.header && decoded.signature == raw.signature,
          "synthetic LZO/offset envelope must preserve all raw bytes");
    check(decoded.terrain_offset == raw.terrain_offset && decoded.tile_types_offset == raw.tile_types_offset &&
          decoded.property_offset == raw.property_offset && decoded.tail_offset == raw.tail_offset, "synthetic table boundaries");
    const auto map = original_map_resources(decoded, 10);
    check(map.roads.size() == 4 && map.roads[0].type == 20 && map.roads[3].type == 7, "special_xy overrides type only at its tile");
    const std::vector<OriginalRoadEdge> expected{{0,2,0},{0,1,3},{1,3,0},{1,0,1},{2,0,2},{2,3,3},{3,2,1},{3,1,2}};
    check(map.edges == expected, "directions down/left/up/right with no row wrapping or out-of-map edges");
    check(map.properties.size() == 2 && map.properties[0].kind == -1 && map.properties[0].sprite_type == 12 &&
          map.properties[0].price == 500 && map.properties[1].kind == 1 && map.properties[1].level == 1 &&
          map.properties[1].price == 510, "sprite12 kind0 normalization and referenced property pricing");
    check(map.card_weights.size() == 2 && map.card_weights[0].card == 3 && map.card_weights[0].weight == 4 &&
          map.card_weights[1].card == 27 && map.card_weights[1].weight == 9 && map.pool_a_ids == std::vector<std::int16_t>{27,3} &&
          map.pool_b_ids == std::vector<std::int16_t>{27} && map.parsed_tail_bytes == 172,
          "skip two opaque tail dwords before distinct card pools and retain unknown suffix");
    check(map.human_funds.cash == 1200 && map.human_funds.deposit == 2300 && map.human_funds.tickets == 3400 && map.scale == 4,
          "synthetic independent balances and scale");
}
void decoder_rejections() {
    rejects([] { decode_original_emp(Bytes(19)); }, "original_emp_truncated");
    for (const auto version : {0U, 4U, 0xffffffffU}) {
        auto file = encode_fixture(fixture()); put(file, 16, version);
        rejects([&] { decode_original_emp(file); }, "original_emp_version_unsupported");
    }
    for (const auto dimensions : {std::array<std::uint32_t,2>{0,2}, {2,0}, {32769,1}, {0xffffffff,0xffffffff}}) {
        auto file = encode_fixture(fixture()); put(file, 23304, dimensions[0]); put(file, 23308, dimensions[1]);
        rejects([&] { decode_original_emp(file); }, "original_emp_dimensions_invalid");
    }
    auto bad = fixture(); put(bad.payload, 8, 0);
    rejects([&] { decode_original_emp(encode_fixture(bad)); }, "original_emp_background_invalid");
    bad = fixture(); put(bad.payload, 8, 0x7fffffff); put(bad.payload, 12, 0x7fffffff);
    rejects([&] { decode_original_emp(encode_fixture(bad)); }, "original_emp_array_truncated");
    bad = fixture(); bad.payload.resize(bad.tail_offset - 1);
    rejects([&] { decode_original_emp(encode_fixture(bad)); }, "original_emp_array_truncated");
    auto short_file = encode_fixture(fixture()); short_file.pop_back();
    rejects([&] { decode_original_emp(short_file); }, "original_kpd_lengths_invalid");
    auto huge_declared = encode_fixture(fixture());
    for (std::size_t i = 23433; i < 23437; ++i) huge_declared[i] = 0x3c;
    rejects([&] { decode_original_emp(huge_declared); }, "original_kpd_lengths_invalid");
}
void resource_rejections() {
    auto bad = fixture(); bad.version = 4;
    rejects([&] { original_map_resources(bad, 10); }, "original_map_gameplay_version_unsupported");
    rejects([] { original_map_resources(fixture(), 0); }, "original_map_price_base_invalid");
    bad = fixture(); put(bad.payload, 0, 2);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_coordinate_invalid");
    bad = fixture(); put(bad.payload, bad.terrain_offset + 56, 2);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_coordinate_invalid");
    bad = fixture(); put(bad.payload, bad.property_offset + 56, 0xffffffff);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_property_invalid");
    bad = fixture(); put(bad.payload, bad.property_offset + 56, 0x7fffffff);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_property_invalid");
    for (const std::size_t offset : {104U,108U,112U,120U}) {
        bad = fixture(); put(bad.payload, bad.tail_offset + offset, 0xffffffff);
        rejects([&] { original_map_resources(bad, 10); }, "original_map_tail_value_invalid");
    }
    bad = fixture(); put(bad.payload, bad.tail_offset + 116, 0);
    check(original_map_resources(bad, 10).scale == 0, "resource model must retain literal scale zero for startup policy validation");
    bad = fixture(); put(bad.payload, bad.tail_offset + 120, 0x7fffffff);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_tail_array_truncated");
    bad = fixture(); put(bad.payload, bad.tail_offset + 144, 3);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_card_id_invalid");
    bad = fixture(); put(bad.payload, bad.tail_offset + 136, 32768);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_card_id_invalid");
    bad = fixture(); put(bad.payload, bad.tail_offset + 156, 28);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_pool_card_id_invalid");
    bad = fixture(); put(bad.payload, bad.tail_offset + 160, 27);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_pool_card_id_invalid");
    bad = fixture(); bad.payload.resize(bad.tail_offset + 121);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_record_truncated");
    bad = fixture(); put(bad.payload, bad.tail_offset + 152, 3);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_pool_count_invalid");
    bad = fixture(); put(bad.payload, bad.tail_offset + 168, 28);
    rejects([&] { original_map_resources(bad, 10); }, "original_map_pool_card_id_invalid");
    for (unsigned scenario = 0; scenario < 6; ++scenario) {
        bad = fixture();
        switch (scenario) {
        case 0: bad.width = 0; break;
        case 1: bad.height = 32769; break;
        case 2: bad.terrain_offset = bad.payload.size() + 1; break;
        case 3: bad.tile_types_offset = 1; break;
        case 4: ++bad.property_offset; break;
        case 5: bad.tail_offset = bad.payload.size() + 1; break;
        }
        rejects([&] { original_map_resources(bad, 10); }, "original_map_layout_invalid");
    }
}
void optional_card_tables_and_sprite_casts() {
    auto emp = fixture();
    put(emp.payload, emp.tail_offset + 132, 0);
    emp.payload.resize(emp.tail_offset + 136);
    auto map = original_map_resources(emp, 10);
    check(map.card_weights.empty() && map.pool_a_ids.empty() && map.pool_b_ids.empty() && map.parsed_tail_bytes == 136,
          "zero weights skips both card pools without requiring either count");
    emp = fixture();
    put(emp.payload, emp.tail_offset + 152, 0);
    put(emp.payload, emp.tail_offset + 156, 0);
    emp.payload.resize(emp.tail_offset + 160);
    map = original_map_resources(emp, 10);
    check(map.card_weights.size() == 2 && map.pool_a_ids.empty() && map.pool_b_ids.empty() && map.parsed_tail_bytes == 160,
          "nonempty weight table permits two independent empty pools");
    for (const auto sprite : {255U, 0xffffffffU}) {
        emp = fixture();
        put(emp.payload, emp.property_offset, sprite);
        put(emp.payload, emp.property_offset + 12, 2);
        map = original_map_resources(emp, 10);
        check(map.properties[0].sprite_type == -1 && map.properties[0].kind == (sprite == 255 ? 2 : -1),
              "normalization distinguishes raw DWORD -1 from low byte 255");
    }
}
}
int main() {
    try {
        constexpr std::string_view file = __FILE__;
        const auto root = std::filesystem::path(std::u8string(file.begin(), file.end())).parent_path().parent_path().parent_path();
        synthetic_layout_and_directions();
        decoder_rejections();
        resource_rejections();
        optional_card_tables_and_sprite_casts();
        actual_maps_match_existing_oracles(root);
        std::cout << "PASS all 61 original EMP oracles and resource models, dynamic pools, graph boundaries and invalid resources\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
