#include "richonline_game_end.hpp"

#include <bit>

namespace richnet {
namespace {
void validate_actor(std::int8_t actor) {
    if (actor < 0 || actor >= 8) {
        throw CodecError("richonline_game_end_actor_out_of_range");
    }
}

Bytes game_packet(std::uint16_t opcode, std::uint16_t game_id) {
    Bytes out;
    append_le(out, opcode, 2);
    append_le(out, game_id, 2);
    return out;
}

Bytes actor_packet(std::uint16_t opcode, std::uint16_t game_id, std::int8_t actor) {
    validate_actor(actor);
    auto out = game_packet(opcode, game_id);
    out.push_back(static_cast<std::uint8_t>(actor));
    return out;
}
}

void validate_richonline_leave_request(View plain) {
    if (plain.size() != 2 || read_le(plain) != 0x000a) {
        throw CodecError("richonline_leave_request_shape");
    }
}

Bytes richonline_leave_ack(std::uint16_t game_id) {
    return game_packet(0x4006, game_id);
}

Bytes richonline_stop_game_controls(std::uint16_t game_id) {
    return game_packet(0x400c, game_id);
}

Bytes richonline_victory_notice(std::uint16_t game_id, std::int8_t actor) {
    return actor_packet(0x400d, game_id, actor);
}

Bytes richonline_bankruptcy_notice(std::uint16_t game_id, std::int8_t actor) {
    return richonline_eliminate_actor(game_id, actor);
}

Bytes richonline_eliminate_actor(std::uint16_t game_id, std::int8_t actor) {
    return actor_packet(0x400e, game_id, actor);
}

Bytes richonline_show_game_results(std::uint16_t game_id, bool show_text_270) {
    auto out = game_packet(0x400f, game_id);
    out.push_back(show_text_270 ? 1 : 0);
    return out;
}

RichonlineGameResultRecord decode_richonline_game_result(View plain) {
    if (plain.size() != 20 || read_le(plain.first(2)) != 0x401b) {
        throw CodecError("richonline_game_result_shape");
    }
    const auto actor = std::bit_cast<std::int8_t>(plain[4]);
    validate_actor(actor);
    return {
        static_cast<std::uint16_t>(read_le(plain.subspan(2, 2))),
        actor,
        std::bit_cast<std::int8_t>(plain[5]),
        std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(6, 2)))),
        read_le(plain.subspan(8, 4)),
        read_le(plain.subspan(12, 4)),
        plain[16], plain[17], plain[18], plain[19],
    };
}

Bytes encode_richonline_game_result(const RichonlineGameResultRecord& record) {
    auto out = actor_packet(0x401b, record.game_id, record.actor);
    out.push_back(static_cast<std::uint8_t>(record.rank_image_index));
    append_le(out, static_cast<std::uint16_t>(record.experience_award), 2);
    append_le(out, record.returned_gold, 4);
    append_le(out, record.bonus_gold, 4);
    out.push_back(record.winner_flag);
    out.push_back(record.escaped_flag);
    out.push_back(record.opaque_18);
    out.push_back(record.level_up_flag);
    return out;
}
}
