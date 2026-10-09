#pragma once

#include "codec.hpp"
#include <variant>

namespace richnet {
struct RichonlineCardDiscardRequest50 {
    std::uint16_t calendar_counter;
    std::int8_t inventory_slot;
    std::uint8_t opaque5;
};
enum class RichonlineTargetCard : std::uint16_t {
    mine1044=109, missile1046=111, nuclear1063=124, safe_nuclear1075=133
};
struct RichonlineTargetCardRequest {
    RichonlineTargetCard kind;
    std::uint16_t calendar_counter;
    std::int8_t inventory_slot, inventory_bank;
    std::int16_t target;
};
RichonlineCardDiscardRequest50 parse_richonline_card_discard50(View plain);
RichonlineTargetCardRequest parse_richonline_target_card(View plain);
Bytes encode_richonline_card_discard4033(std::uint16_t game_id,std::int8_t slot,std::int8_t actor);
Bytes encode_richonline_mine40bd(std::uint16_t game_id,const RichonlineTargetCardRequest& request);
// The attacker identity (0..7) is supplied by authoritative turn state; it is not request byte +8.
Bytes encode_richonline_missile40bf(std::uint16_t game_id,const RichonlineTargetCardRequest& request,
    std::int8_t attacker);
Bytes encode_richonline_nuclear40cc(std::uint16_t game_id,const RichonlineTargetCardRequest&,std::int8_t attacker);
Bytes encode_richonline_safe_nuclear40d5(std::uint16_t game_id,const RichonlineTargetCardRequest&,std::int8_t attacker);
}
