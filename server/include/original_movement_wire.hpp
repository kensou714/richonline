#pragma once

#include "codec.hpp"
#include <variant>

namespace richnet {
enum class OriginalMoveKind { normal, special };
struct OriginalRollRequest { std::uint16_t context; std::uint32_t parameter; };
struct OriginalMoveReport { OriginalMoveKind kind; std::uint16_t context; std::int16_t tile; };
struct OriginalDiceChoice { std::uint16_t context; std::int8_t count; std::uint8_t opaque; };
struct OriginalDirectionChoice { std::uint16_t context; std::int8_t direction; std::uint8_t opaque; };
using OriginalMovementRequest = std::variant<OriginalRollRequest, OriginalMoveReport, OriginalDiceChoice, OriginalDirectionChoice>;

struct OriginalRollRoute {
    std::uint16_t gmsv_id;
    std::int16_t start_tile;
    std::uint8_t dice_count;
    std::array<std::uint8_t,3> faces;
    std::vector<std::uint8_t> directions;
    std::array<std::uint8_t,13> route_storage;
    std::uint32_t gold_charge;
};
struct OriginalLanding {
    std::uint16_t gmsv_id;
    std::int16_t tile;
    Bytes opaque_suffix;
};
struct OriginalDirectionResult {
    std::uint16_t gmsv_id;
    std::int8_t direction;
    Bytes opaque_suffix;
};

OriginalMovementRequest parse_original_movement_request(View plain);
Bytes encode_original_roll_route(const OriginalRollRoute& route);
Bytes encode_original_landing(const OriginalLanding& landing);
Bytes encode_original_direction_result(const OriginalDirectionResult& result);
}
