#include "richonline_boss_startup.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_map_package.hpp"
#include "original_map.hpp"
#include "richonline_initial_cash.hpp"
#include "richonline_combat_resources.hpp"
#include "richonline_room_board.hpp"

#include <algorithm>
#include <string_view>

namespace richnet {
namespace {
std::uint32_t word(View bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4) throw CodecError("richonline_boss_resource_truncated");
    return read_le(bytes.subspan(offset,4));
}

}
RichonlineBossStartup build_richonline_boss_startup(const std::filesystem::path& client_root,
    const RichonlineRoomSnapshot& room, const RichonlineBossStartupInput& input) {
    const auto& extension = room.description.extension;
    const View e(extension), record(room.description.record);
    if (e.size() != 88 || word(record,120) != 88 || (word(record,32)&0x40U) == 0)
        throw CodecError("richonline_boss_E88_invalid");
    if (input.human_identity < 0 || room.participants.size() != 1 || room.owner != static_cast<std::uint32_t>(input.human_identity) ||
        room.participants.front().actor != room.owner || !room.participants.front().ready)
        throw CodecError("richonline_boss_membership_invalid");
    RichonlineCombatModifierResources::load(client_root).validate_supported_equipment(input.profile_slots);
    if (std::any_of(input.building_skill_caps.begin(),input.building_skill_caps.end(),[](auto v) { return v < 0 || v > 7; }))
        throw CodecError("richonline_boss_skill_caps_invalid");
    const auto name_end = std::find(e.begin(),e.begin()+32,std::uint8_t{0});
    const std::string map_name(e.begin(),name_end);
    if (word(e,48) != 3) throw CodecError("richonline_boss_mode_unsupported");
    if (word(e,52) != 1) throw CodecError("richonline_boss_capacity_unsupported");
    if (word(record,36) != word(e,48) || word(record,40) != word(e,52))
        throw CodecError("richonline_boss_public_room_mismatch");
    const auto stage = load_richonline_boss_stage(client_root,map_name,word(e,68));
    if (!std::equal(stage.signature.begin(),stage.signature.end(),e.begin()+32)) throw CodecError("richonline_boss_map_signature_mismatch");
    if (stage.player_count_choices != std::vector<std::uint32_t>{1,2,3,4}) throw CodecError("richonline_boss_stage_unsupported");
    if (word(e,56) != stage.wait_seconds || word(e,60) != stage.game_months || word(e,64) != stage.pawn_gold)
        throw CodecError("richonline_boss_room_resource_mismatch");
    const auto map = load_original_emp(client_root / "Map" / stage.map_name);
    const auto& package=find_richonline_map_package(stage.map_name,stage.category);
    std::array<RichonlineMapSpawnChoice,2> positions{};
    try {
        positions=choose_richonline_map_spawns(richonline_road_topology(map),package.resource_rules.spawn_policy,input.spawn_random);
    } catch(const CodecError& error) {
        if(std::string_view(error.what())=="richonline_map_rules_spawn_graph_disconnected")
            throw CodecError("richonline_boss_spawn_graph_disconnected");
        throw;
    }
    const auto& w = input.wire;
    RichonlineBoardInit init{w.game_server_id,w.opaque_f64,w.year,w.month,w.day,w.weekday,0,w.opaque_header_byte,{}};
    const RichonlineInitialCash cash(client_root);
    const auto initial_boss_cash = cash.apply(stage.boss.base_cash,stage.boss.equipment);
    // NEW7F3C70 对人类和 BOSS 都应用同一套初始现金加成；快照覆盖客户端本地值。
    const auto initial_human_cash = cash.apply(stage.human.cash,input.profile_slots);
    // New 7DF010 tail fields26..29; 7F3840 explicitly initializes BOSS deposit/tickets to0.
    RichonlineBoardSnapshot snapshot{w.game_server_id,w.calendar_counter,stage.monetary_scale,{}};
    const std::array<RichonlineRoomBoardPlayer,1> players{{{room.participants.front().connection,
        {input.human_identity,positions[0].position,positions[0].direction,input.building_skill_caps,w.opaque_trailing[0]},
        {initial_human_cash,stage.human.deposit,stage.human.tickets}}}};
    const std::array<RichonlineRoomBoardSynthetic,1> synthetic{{{
        {-1,positions[1].position,positions[1].direction,w.synthetic_unconsumed_skill_bytes,w.opaque_trailing[1]},
        {initial_boss_cash,0,0}}}};
    auto boards=build_richonline_room_boards(room,std::move(init),std::move(snapshot),players,synthetic);
    return {room,std::move(boards.front().init),std::move(boards.front().snapshot),w.envelope,input.profile_slots};
}
}
