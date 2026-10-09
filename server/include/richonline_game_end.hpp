#pragma once

#include "codec.hpp"

namespace richnet {

// NEW RnClient.exe only. These are packet consumers' proven byte layouts;
// assigning rewards and deciding victory belong to the map/game rules.
void validate_richonline_leave_request(View plain);
Bytes richonline_leave_ack(std::uint16_t game_id);
Bytes richonline_stop_game_controls(std::uint16_t game_id);
Bytes richonline_bankruptcy_notice(std::uint16_t game_id, std::int8_t actor);
Bytes richonline_eliminate_actor(std::uint16_t game_id, std::int8_t actor);
Bytes richonline_show_game_results(std::uint16_t game_id, bool show_text_270);

// NEW G_ZanJiList.ui identifies experience, returned gold, bonus and level-up.
// Byte18 remains unresolved. Every field must be supplied by the caller.
struct RichonlineGameResultRecord {
    std::uint16_t game_id;
    std::int8_t actor;
    std::int8_t rank_image_index;
    std::int16_t experience_award;
    std::uint32_t returned_gold;
    std::uint32_t bonus_gold;
    std::uint8_t winner_flag;
    std::uint8_t escaped_flag;
    std::uint8_t opaque_18;
    std::uint8_t level_up_flag;
};

RichonlineGameResultRecord decode_richonline_game_result(View plain);
Bytes encode_richonline_game_result(const RichonlineGameResultRecord& record);

}
