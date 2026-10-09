#pragma once
#include "original_route.hpp"

namespace richnet {
struct OriginalAttachedBomb {
    std::uint8_t steps;
    std::int8_t owner;
    bool operator==(const OriginalAttachedBomb&) const = default;
};
struct OriginalBombOccupant {
    std::uint8_t slot;
    std::int16_t tile;
    bool active;
    std::int8_t status1493, status1489;
    std::optional<OriginalAttachedBomb> bomb;
};
struct OriginalBombRoster {
    std::uint8_t mover = 0;
    bool countdown_enabled = true;
    std::optional<OriginalAttachedBomb> attached;
    std::vector<OriginalBombOccupant> others;
};
struct OriginalBombTransfer {
    std::size_t step;
    std::uint8_t target;
};
struct OriginalBombPrediction {
    OriginalBombRoster after;
    std::optional<std::size_t> explosion_step;
    std::vector<OriginalBombTransfer> transfers;
    std::optional<std::int8_t> exploded_owner;
};
void validate_original_bombs(const OriginalBombRoster& roster);
OriginalBombPrediction predict_original_bombs(const OriginalBombRoster& roster, const OriginalRouteTrace& route);
}
