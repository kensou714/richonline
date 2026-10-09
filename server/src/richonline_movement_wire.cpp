#include "richonline_movement_wire.hpp"

#include <bit>

namespace richnet {
RichonlineMovementRequest parse_richonline_movement_request(View plain) {
    if (plain.size() < 2) throw CodecError("richonline_movement_length_invalid");
    const auto opcode = read_le(plain.first(2));
    switch (opcode) {
    case 0x10: case 0x11: case 0x12: case 0x14: case 0x28: case 0x2a: break;
    default: throw CodecError("richonline_movement_opcode_unsupported");
    }
    if (plain.size() != (opcode == 0x10 ? 8U : 6U))
        throw CodecError("richonline_movement_length_invalid");
    const auto counter = static_cast<std::uint16_t>(read_le(plain.subspan(2,2)));
    if (opcode == 0x10) return RichonlineMoveRequest10{counter,read_le(plain.subspan(4,4))};
    if (opcode == 0x14) {
        if(plain[4]<1 || plain[4]>3) throw CodecError("richonline_movement_dice_count_invalid");
        return RichonlineDiceChoice14{counter,plain[4],plain[5]};
    }
    const auto endpoint = std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(4,2))));
    switch (opcode) {
    case 0x11: return RichonlineMoveStop11{counter,endpoint};
    case 0x12: return RichonlineMoveCountdown12{counter,endpoint};
    case 0x28: return RichonlineMovePause28{counter,endpoint};
    case 0x2a: return RichonlineMoveSpecialTile2A{counter,endpoint};
    default: throw CodecError("richonline_movement_opcode_unsupported");
    }
}

Bytes encode_richonline_turn4010(const RichonlineTurn4010& turn, std::uint8_t opaque7) {
    if (turn.actor_slot < 0 || turn.actor_slot >= 8)
        throw CodecError("richonline_movement_actor_slot_invalid");
    if (turn.round_anchor_slot < 0 || turn.round_anchor_slot >= 8)
        throw CodecError("richonline_movement_round_anchor_invalid");
    Bytes output;
    append_le(output,0x4010,2);
    append_le(output,turn.game_server_id,2);
    output.push_back(std::bit_cast<std::uint8_t>(turn.actor_slot));
    output.push_back(std::bit_cast<std::uint8_t>(turn.round_anchor_slot));
    output.push_back(turn.animation_replay_flag);
    output.push_back(opaque7);
    return output;
}

Bytes encode_richonline_route4011(const RichonlineRoute4011& route, const RichonlineRouteWirePolicy& policy) {
    if (route.start_position < 0) throw CodecError("richonline_movement_start_position_invalid");
    if (route.dice_count < 1 || route.dice_count > 3)
        throw CodecError("richonline_movement_dice_count_invalid");
    if (route.directions.empty() || route.directions.size() > 36)
        throw CodecError("richonline_movement_direction_count_invalid");
    int budget = 0;
    for (std::size_t i = 0; i < route.dice_count; ++i) {
        if (route.ui_dice[i] < 0) throw CodecError("richonline_movement_dice_budget_invalid");
        budget += route.ui_dice[i];
    }
    if (budget < 1 || budget > 36) throw CodecError("richonline_movement_dice_budget_invalid");
    if (route.required_route_steps < static_cast<std::size_t>(budget) ||
        route.required_route_steps > route.directions.size())
        throw CodecError("richonline_movement_route_coverage_invalid");
    if (policy.optional_tail.size() > 260) throw CodecError("richonline_movement_tail_too_large");
    Bytes output;
    append_le(output,0x4011,2);
    append_le(output,route.game_server_id,2);
    append_le(output,std::bit_cast<std::uint16_t>(route.start_position),2);
    output.push_back(route.dice_count);
    output.push_back(static_cast<std::uint8_t>(route.directions.size()));
    for (const auto die : route.ui_dice) output.push_back(std::bit_cast<std::uint8_t>(die));
    output.resize(20,0);
    for (std::size_t i = 0; i < route.directions.size(); ++i) {
        const auto direction = static_cast<std::uint8_t>(route.directions[i]);
        if (direction > 3) throw CodecError("richonline_movement_direction_invalid");
        output[11+i/4] |= static_cast<std::uint8_t>(static_cast<unsigned>(direction) << (2*(i%4)));
    }
    output.insert(output.end(),policy.opaque20_23.begin(),policy.opaque20_23.end());
    append_le(output,std::bit_cast<std::uint32_t>(policy.local_reserve_charge),4);
    output.insert(output.end(),policy.optional_tail.begin(),policy.optional_tail.end());
    return output;
}

Bytes encode_richonline_empty_turn420f(std::uint16_t game_server_id) {
    Bytes output;
    append_le(output,0x420f,2);
    append_le(output,game_server_id,2);
    append_le(output,0xffff,2);
    return output;
}
}
