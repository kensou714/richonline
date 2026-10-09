#include "richonline_boss_startup.hpp"
#include "richonline_map_package.hpp"
#include "original_map.hpp"
#include "original_options.hpp"
#include "../vendor/lzokay/lzokay.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string_view>
#include <tuple>

namespace {
using namespace richnet;
void check(bool value, std::string_view reason) {
    if (!value) throw std::runtime_error(std::string(reason));
}
template<class F> void rejects(F action, std::string_view code) {
    try { action(); } catch (const CodecError& error) { check(error.what() == code, error.what()); return; }
    throw std::runtime_error("expected_rejection");
}
void put(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) bytes.at(offset + i) = static_cast<std::uint8_t>(value >> (8 * i));
}
RichonlineBossStartupInput input() {
    return {25, {}, {7,7,7,7,7,7,7,7,7,7},
        {0x1234, 0x56789abc, 2026, 10, 9, 5, {0,0,0,0,0,0,0xf0,0x3f},
         0xa9, {0xb9,0xc9}, {1,2,3,4,5,6,7,8,9,10}, {0x321,-7}}};
}
RichonlineRoomSnapshot room(const std::filesystem::path& root, std::string_view name = "BS_1_1.emp", std::uint32_t pawn = 100) {
    RichonlineRoomSnapshot result{3,25,{},{{1,25,0,true}}};
    auto& e = result.description.extension;
    e = Bytes(88, 0xa5);
    std::fill_n(e.begin(), 32, std::uint8_t{0});
    std::copy(name.begin(), name.end(), e.begin());
    const auto emp = load_original_emp(root / "Map" / name);
    std::copy(emp.signature.begin(), emp.signature.end(), e.begin() + 32);
    put(e,48,3); put(e,52,1); put(e,56,10); put(e,60,3); put(e,64,pawn); put(e,68,0);
    result.description.record[32] = 0x40;
    result.description.record[36] = 3;
    result.description.record[40] = 1;
    result.description.record[120] = 88;
    result.description.record[124] = 1;
    return result;
}
void actual_new_resources(const std::filesystem::path& root) {
    const auto source = room(root);
    const std::array<std::uint8_t,16> expected_signature{0x77,0x2a,0x81,0xa7,0x87,0x67,0x85,0x52,
        0x15,0x57,0x8e,0xcf,0xf3,0x9c,0x3a,0xbe};
    check(std::equal(expected_signature.begin(),expected_signature.end(),source.description.extension.begin()+32),
          "test_requires_actual_new_client_map");
    const auto plan = build_richonline_boss_startup(root, source, input());
    check(plan.room.description.extension == source.description.extension &&
          plan.room.description.record == source.description.record, "E88_or_record_not_preserved");
    check(plan.init.participants.size() == 2 && plan.init.local_slot == 0 &&
          plan.init.participants[0].lobby_identity == 25 && plan.init.participants[1].lobby_identity == -1,
          "two_slot_identity_layout_wrong");
    check(plan.init.participants[0].position == 115 && plan.init.participants[1].position == 236 &&
          plan.init.participants[0].direction == 1 && plan.init.participants[1].direction == 1,
          "resource_derived_spawns_wrong");
    check(plan.snapshot.slots[0].cash == 20000 && plan.snapshot.slots[0].deposit == 0 &&
          plan.snapshot.slots[0].tickets == 150 && plan.snapshot.slots[1].cash == 100000 &&
          plan.snapshot.slots[1].deposit == 0 && plan.snapshot.slots[1].tickets == 0 &&
          plan.snapshot.monetary_scale == 1, "new_resource_funds_wrong");
    const auto packet = encode_richonline_board_init(plan.init);
    check(packet.size() == 52 && packet[19] == 0xa9 && packet[35] == 0xb9 && packet[51] == 0xc9 &&
          packet[25] == 7 && packet[41] == 1 && packet[50] == 10, "new_layout_or_explicit_opaque_bytes_wrong");
    check(plan.snapshot.calendar_counter == 0x56789abc && plan.snapshot.game_server_id == 0x1234 &&
          plan.envelope.tag == 0x321 && plan.envelope.mode == -7, "session_domains_not_preserved");
    check(encode_richonline_board_snapshot(plan.snapshot).size() == 36, "snapshot_slot_stride_wrong");
    auto equipped=input(); equipped.profile_slots[13]=13;
    const auto with_certificate=build_richonline_boss_startup(root,source,equipped);
    check(encode_richonline_board_init(with_certificate.init)==encode_richonline_board_init(plan.init) &&
          encode_richonline_board_snapshot(with_certificate.snapshot)==encode_richonline_board_snapshot(plan.snapshot),
          "rp_certificate_changed_game_initialization");
    equipped.profile_slots[13]=0x1000d;
    rejects([&]{build_richonline_boss_startup(root,source,equipped);},"richonline_boss_profile_slots_nonempty");
}
void remaining_first_chapter_maps_use_their_resources(const std::filesystem::path& root) {
    struct Expected { std::string_view name; std::uint32_t pawn,cash,tickets,boss_cash; std::int16_t human,boss; std::uint8_t boss_dir; };
    const std::array cases{
        Expected{"BS_1_2.emp",500,15000,300,100000,99,220,0},
        Expected{"BS_1_3.emp",1000,20000,300,120000,85,233,1},
        Expected{"BS_1_4.emp",1500,18000,300,150000,84,235,1}};
    for (const auto& expected : cases) {
        const auto source=room(root,expected.name,expected.pawn);
        const auto plan=build_richonline_boss_startup(root,source,input());
        check(plan.init.participants[0].position==expected.human && plan.init.participants[0].direction==1 &&
              plan.init.participants[1].position==expected.boss && plan.init.participants[1].direction==expected.boss_dir,
              "selected_map_spawn_policy_wrong");
        check(plan.snapshot.slots[0].cash==expected.cash && plan.snapshot.slots[0].tickets==expected.tickets &&
              plan.snapshot.slots[0].deposit==0 && plan.snapshot.slots[1].cash==expected.boss_cash &&
              plan.snapshot.slots[1].deposit==0 && plan.snapshot.slots[1].tickets==0,
              "selected_map_initial_balances_wrong");
        check(plan.room.description.extension==source.description.extension && plan.snapshot.monetary_scale==1,
              "selected_map_room_or_scale_changed");
        auto bad=source; put(bad.description.extension,64,100);
        rejects([&]{build_richonline_boss_startup(root,bad,input());},"richonline_boss_room_resource_mismatch");
        bad=source; bad.description.extension[32]^=1;
        rejects([&]{build_richonline_boss_startup(root,bad,input());},"richonline_boss_map_signature_mismatch");
    }
}
void bad_room_or_profile_is_rejected(const std::filesystem::path& root) {
    auto source = room(root); auto person = input();
    person.profile_slots[7] = 31;
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_boss_profile_slots_nonempty");
    person = input(); person.building_skill_caps[0] = -1;
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_boss_skill_caps_invalid");
    person = input(); source.description.extension[32] ^= 1;
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_boss_map_signature_mismatch");
    for (const auto [offset,value,code] : {
        std::tuple<std::size_t,std::uint32_t,std::string_view>{48,1,"richonline_boss_mode_unsupported"},
        {52,2,"richonline_boss_capacity_unsupported"}, {68,2,"richonline_stage_map_unsupported"},
        {56,20,"richonline_boss_room_resource_mismatch"}}) {
        source = room(root); put(source.description.extension,offset,value);
        rejects([&] { build_richonline_boss_startup(root,source,person); }, code);
    }
    source = room(root); source.participants[0].actor = 26;
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_boss_membership_invalid");
    source = room(root); source.description.extension.pop_back();
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_boss_E88_invalid");
    source = room(root); source.description.record[36] = 1;
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_boss_public_room_mismatch");
    source = room(root); source.description.record[40] = 2;
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_boss_public_room_mismatch");
    source = room(root); put(source.description.extension,68,99);
    check(build_richonline_boss_startup(root,source,person).room.description.extension == source.description.extension,
          "invented_category_upper_bound");
    put(source.description.extension,68,0xffffffffU);
    check(build_richonline_boss_startup(root,source,person).room.description.extension == source.description.extension,
          "boss_category_bits_not_preserved");
    source = room(root); person.wire.month = 2; person.wire.day = 30;
    rejects([&] { build_richonline_boss_startup(root,source,person); }, "richonline_board_calendar_invalid");
    source = room(root,"V_BS_1_1.emp",0); put(source.description.extension,68,2);
    const auto special=build_richonline_boss_startup(root,source,input());
    check(special.room.description.extension==source.description.extension &&
          special.init.participants[0].position==99 && special.init.participants[1].position==106 &&
          special.snapshot.slots[0].cash==12000 && special.snapshot.slots[0].tickets==350 &&
          special.snapshot.slots[1].cash==150000 && special.init.participants[1].lobby_identity==-1,
          "zhao_initialization_mixed_with_ordinary_stage");
    put(source.description.extension,68,0);
    rejects([&] { build_richonline_boss_startup(root,source,input()); }, "richonline_stage_map_unsupported");
    source = room(root,"BS_2_1.emp",100);
    rejects([&] { build_richonline_boss_startup(root,source,input()); }, "richonline_boss_room_resource_mismatch");
    source = room(root,"BS_2_1.emp",500);
    const auto azhanbo=build_richonline_boss_startup(root,source,input());
    check(azhanbo.room.description.extension==source.description.extension && azhanbo.init.participants.size()==2 &&
          azhanbo.snapshot.slots[1].cash==100000,"azhanbo_initialization_not_resource_driven");
    const auto& bs22_package=find_richonline_map_package("BS_2_2.emp",0);
    const auto bs22_stage=bs22_package.load_stage(root,0);
    source=room(root,"BS_2_2.emp",bs22_stage.pawn_gold);
    const auto bs22=build_richonline_boss_startup(root,source,input());
    check(bs22.init.participants.size()==2 && bs22.init.participants[0].position==83 &&
          bs22.init.participants[0].direction==1 && bs22.init.participants[1].position==233 &&
          bs22.init.participants[1].direction==1,
          "BS_2_2_startup_did_not_use_package_selected_component");
}
Bytes packed(View plain) {
    Bytes compressed(lzokay::compress_worst_size(plain.size()));
    std::size_t size = 0;
    check(lzokay::compress(plain.data(),plain.size(),compressed.data(),compressed.size(),size) == lzokay::EResult::Success,
          "fixture_compression_failed");
    Bytes result{42};
    append_le(result,static_cast<std::uint32_t>(plain.size()),4);
    append_le(result,static_cast<std::uint32_t>(size),4);
    result.insert(result.end(),compressed.begin(),compressed.begin()+static_cast<std::ptrdiff_t>(size));
    for (std::size_t i = 1; i < result.size(); ++i) result[i] = static_cast<std::uint8_t>(result[i]+42);
    return result;
}
void write(const std::filesystem::path& path, View bytes) {
    std::ofstream stream(path,std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    check(static_cast<bool>(stream),"fixture_write_failed");
}
struct Resources {
    std::filesystem::path root;
    explicit Resources(const std::filesystem::path& source, std::string_view map_name = "BS_1_1.emp") : root(std::filesystem::temp_directory_path() /
        ("richonline-boss-init-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))) {
        std::filesystem::create_directories(root / "Map");
        std::filesystem::create_directories(root / "Data");
        for (const auto name : {"Data/BossWar.kpd","Data/Prop.kpd"})
            std::filesystem::copy_file(source / name,root / name);
        std::filesystem::copy_file(source / "Map" / map_name,root / "Map" / map_name);
    }
    ~Resources() { std::error_code error; std::filesystem::remove_all(root,error); }
};
void changed_resources_drive_funds_and_spawns(const std::filesystem::path& root) {
    struct Case { std::string_view name; std::uint32_t pawn,boss_cash; std::int16_t spawn; };
    for (const auto& test : {Case{"BS_1_1.emp",100,110800,115},Case{"BS_1_3.emp",1000,132800,85}}) {
        Resources fixture(root,test.name);
        auto props = load_original_kpd(root / "Data" / "Prop.kpd");
        constexpr std::string_view item = "\n[PROP]\nindx=31\natt_desc=fixture\nmoneyV=800\nmoneyR=10(<200000)\n";
        props.insert(props.end(),item.begin(),item.end());
        write(fixture.root / "Data" / "Prop.kpd",packed(props));
        auto map = load_original_emp(root / "Map" / test.name);
        map.payload[map.terrain_offset+static_cast<std::size_t>(test.spawn)*64] = 0xff;
        put(map.payload,map.tail_offset+104,23456); put(map.payload,map.tail_offset+112,456);
        put(map.payload,map.tail_offset+116,2);
        const auto block = packed(map.payload);
        auto file = map.header; file.insert(file.end(),block.begin(),block.end());
        write(fixture.root / "Map" / test.name,file);
        auto person = input(); person.wire.opaque_f64 = {1,2,3,4,5,6,7,8};
        const auto plan = build_richonline_boss_startup(fixture.root,room(root,test.name,test.pawn),person);
        check(plan.init.participants[0].position != test.spawn && plan.snapshot.slots[1].cash == test.boss_cash &&
              plan.snapshot.slots[0].cash == 23456 && plan.snapshot.slots[0].tickets == 456 && plan.snapshot.monetary_scale == 2,
              "builder_ignored_changed_resource_graph_or_effects");
        check(plan.init.opaque_f64 == person.wire.opaque_f64,"explicit_f64_policy_replaced");
    }
}
void disconnected_candidates_are_rejected(const std::filesystem::path& root) {
    Resources fixture(root);
    auto map = load_original_emp(root / "Map" / "BS_1_1.emp");
    for (std::size_t i = 0; i < static_cast<std::size_t>(map.width)*map.height; ++i)
        map.payload[map.terrain_offset+i*64] = 0xff;
    for (const std::size_t i : {34U,35U,36U,66U,67U,68U}) map.payload[map.terrain_offset+i*64] = 8;
    auto file = map.header; const auto block = packed(map.payload); file.insert(file.end(),block.begin(),block.end());
    write(fixture.root / "Map" / "BS_1_1.emp",file);
    rejects([&] { build_richonline_boss_startup(fixture.root,room(root),input()); }, "richonline_boss_spawn_graph_disconnected");
}
}
int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("usage: richonline_boss_startup_tests <Richonline-resource-root>");
        const std::filesystem::path root(argv[1]);
        actual_new_resources(root); remaining_first_chapter_maps_use_their_resources(root); bad_room_or_profile_is_rejected(root);
        changed_resources_drive_funds_and_spawns(root); disconnected_candidates_are_rejected(root);
        std::cout << "PASS new-client BOSS initialization resources and explicit wire inputs\n";
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
