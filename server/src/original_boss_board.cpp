#include "original_boss_board.hpp"
#include <algorithm>

namespace richnet {
OriginalBossBoard prepare_original_boss_board(OriginalMapResources map,
    const OriginalBossConfig& config, const OriginalBossBoardRequest& request) {
    const View wire(request.room.wire);
    if (wire.size() != 208 || read_le(wire.subspan(120,4)) != 80 ||
        request.room.max_players != 1 || read_le(wire.subspan(40,4)) != 1 || read_le(wire.subspan(44,4)) != 1 ||
        read_le(wire.subspan(176,4)) != 3 || read_le(wire.subspan(180,4)) != 1)
        throw CodecError("original_boss_requires_single_player_room");
    if (read_le(wire.subspan(196,4)) == 2) throw CodecError("original_boss_advanced_room_unsupported");
    if (!request.room.map_name.ends_with(".emp")) throw CodecError("original_boss_map_mismatch");
    const auto stage_id = request.room.map_name.substr(0,request.room.map_name.size()-4);
    const auto settings = config.playable(stage_id);
    const auto name = wire.subspan(128,32);
    const auto end = std::find(name.begin(),name.end(),std::uint8_t{0});
    if (end == name.end()) throw CodecError("original_boss_map_mismatch");
    auto wire_name = std::string(name.begin(),end);
    // Original map catalog accepts the bare stem and ASCII case variants.
    std::transform(wire_name.begin(),wire_name.end(),wire_name.begin(),[](unsigned char ch) {
        return static_cast<char>(ch >= 'a' && ch <= 'z' ? ch-('a'-'A') : ch);
    });
    auto expected_name = request.room.map_name;
    std::transform(expected_name.begin(),expected_name.end(),expected_name.begin(),[](unsigned char ch) {
        return static_cast<char>(ch >= 'a' && ch <= 'z' ? ch-('a'-'A') : ch);
    });
    if (wire_name != expected_name && wire_name != stage_id) throw CodecError("original_boss_map_mismatch");
    if (!std::equal(map.emp.signature.begin(),map.emp.signature.end(),wire.begin()+160))
        throw CodecError("original_boss_map_signature_mismatch");
    if (request.human_user_id < 0) throw CodecError("original_boss_human_identity_invalid");
    for (const auto spawn : {request.human_spawn,request.boss_spawn}) {
        if (std::none_of(map.edges.begin(),map.edges.end(),[&](const auto& edge) {
            return edge.from == spawn.tile && edge.direction == spawn.direction;
        })) throw CodecError("original_boss_spawn_invalid");
    }
    std::array<std::uint8_t,10> skills;
    skills.fill(settings.max_building_skills);
    OriginalStartup startup{
        {request.instance,request.game_value,request.calendar,0,
            {{request.human_user_id,request.human_spawn.tile,request.human_spawn.direction,skills,request.human_alignment},
             {-1,request.boss_spawn.tile,request.boss_spawn.direction,request.boss_record_skills,request.boss_alignment}},
            request.header_alignment,request.init_suffix},
        {request.instance,request.context,map.scale,{settings.human,settings.boss},request.snapshot_suffix},
        request.envelope};
    validate_original_startup(startup);
    return {std::move(map),settings,std::move(startup)};
}
}
