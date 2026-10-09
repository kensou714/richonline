#include "original_boss_board.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <bit>
#include <functional>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
void rejects(const std::function<void()>& action, std::string_view reason) {
    try { action(); } catch (const CodecError& error) { check(error.what() == reason,"wrong rejection"); return; }
    throw std::runtime_error("expected rejection");
}
void set_word(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) bytes.at(offset+index) = static_cast<std::uint8_t>(value >> (8U*index));
}
OriginalBossBoardRequest request_for(const OriginalMapResources& map, std::string name,
    OriginalBossSpawn human, OriginalBossSpawn boss) {
    Bytes wire(208);
    wire[0] = 'T';
    std::copy(name.begin(),name.end(),wire.begin()+128);
    std::copy(map.emp.signature.begin(),map.emp.signature.end(),wire.begin()+160);
    for (auto offset : {40U,44U,180U}) set_word(wire,offset,1);
    set_word(wire,32,0x40); set_word(wire,120,80); set_word(wire,176,3);
    return {{std::move(wire),std::move(name),1},27,human,boss,0x1234,0xabcdef00,{2026,10,9,6},3.25,
        {1,2,3,4,5,6,7,6,5,4},0xa1,0xb2,0xc3,{0x91},{0x92},{0,-1,{0x81,0x82,0x83,0x84}}};
}
}
int main() {
    try {
        constexpr std::u8string_view source = RICHONLINE_LEGACY_RESOURCE_ROOT;
        const auto root = std::filesystem::path(std::u8string(source.begin(),source.end()));
        const auto config = OriginalBossConfig::load(root/"local-server"/"boss-stages.json",{1038,1044,1046,1063,1075});
        const auto price = load_original_price_base(root/"Data"/"Option.kpd");
        constexpr std::array<OriginalBossSpawn,4> humans{{{115,3},{98,3},{85,3},{89,0}}};
        constexpr std::array<OriginalBossSpawn,4> bosses{{{123,1},{236,1},{230,3},{230,3}}};
        constexpr std::array<std::uint32_t,4> human_cash{100000,15000,20000,18000};
        constexpr std::array<std::uint32_t,4> boss_cash{100000,100000,120000,150000};
        for (std::size_t index = 0; index < 4; ++index) {
            const auto name = "BS_1_"+std::to_string(index+1)+".emp";
            const auto map = original_map_resources(load_original_emp(root/"Map"/name),price);
            auto request = request_for(map,name,humans[index],bosses[index]);
            const auto board = prepare_original_boss_board(map,config,request);
            const auto init = encode_original_board_init(board.startup.init);
            const auto snapshot = encode_original_board_snapshot(board.startup.snapshot);
            check(init.size() == 53 && init[17] == 2 && init[18] == 0,"two participants/local human");
            check(read_le(View(init).subspan(20,2)) == 27 && read_le(View(init).subspan(36,2)) == 65535,"human/AI wire identity");
            check(read_le(View(init).subspan(22,2)) == static_cast<std::uint16_t>(humans[index].tile),"human start");
            check(read_le(View(init).subspan(38,2)) == static_cast<std::uint16_t>(bosses[index].tile),"boss start");
            check(std::all_of(init.begin()+25,init.begin()+35,[](auto byte) { return byte == 7; }),"all human skills full");
            check(init[19] == 0xa1 && init[35] == 0xb2 && init[51] == 0xc3 && init[52] == 0x91,"explicit alignment/suffix retained");
            check(read_le(View(init).subspan(8,4)) == static_cast<std::uint32_t>(std::bit_cast<std::uint64_t>(3.25) >> 32U),"explicit game double");
            check(read_le(View(snapshot).subspan(4,4)) == 0xabcdef00 && read_le(View(snapshot).subspan(8,4)) == map.scale,"map scale/context");
            check(read_le(View(snapshot).subspan(12,4)) == human_cash[index] && read_le(View(snapshot).subspan(24,4)) == boss_cash[index],"stage balances");
            check(board.settings.human_initial_cards == std::vector<std::int16_t>{1038,1044},"remote die/mine loadout");
            check(board.settings.attack.attempts == 4 && board.settings.attack.idle_weight == 80,"BOSS configured attack rules");
            auto unconfigured_scale = map;
            unconfigured_scale.scale = 0;
            rejects([&] { prepare_original_boss_board(unconfigured_scale,config,request); },"original_board_scale_invalid");
            if (index == 0) check(map.human_funds.cash != board.settings.human.cash,"explicit admin balance overrides resource default");
            request.room.wire[160] ^= 1;
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_map_signature_mismatch");
            request.room.wire[160] ^= 1;
            request.human_spawn.tile = -1;
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_spawn_invalid");
            request.human_spawn = humans[index]; request.boss_spawn.direction = 4;
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_spawn_invalid");
            request.boss_spawn = bosses[index]; request.human_user_id = -1;
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_human_identity_invalid");
            request.human_user_id = 27; request.room.wire[176] = 0;
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_requires_single_player_room");
            request.room.wire[176] = 3; request.room.wire[196] = 2;
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_advanced_room_unsupported");
            request.room.wire[196] = 0; request.room.max_players = 2;
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_requires_single_player_room");
            request.room.max_players = 1;
            std::fill(request.room.wire.begin()+128,request.room.wire.begin()+160,0);
            const auto alias = "bs_1_"+std::to_string(index+1);
            std::copy(alias.begin(),alias.end(),request.room.wire.begin()+128);
            check(prepare_original_boss_board(map,config,request).startup.init.players.size() == 2,"accepted map stem alias");
            request.room.wire[128] = 'Z';
            rejects([&] { prepare_original_boss_board(map,config,request); },"original_boss_map_mismatch");
            std::cout << "PASS map-backed " << name << " roads=" << map.roads.size() << " properties=" << map.properties.size()
                << " scale=" << map.scale << " human_cash=" << human_cash[index] << " boss_cash=" << boss_cash[index] << '\n';
        }
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
