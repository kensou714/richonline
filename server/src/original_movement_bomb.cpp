#include "original_movement_bomb.hpp"
#include <algorithm>
#include <set>

namespace richnet {
void validate_original_bombs(const OriginalBombRoster& roster) {
    const auto validate = [](const std::optional<OriginalAttachedBomb>& bomb) {
        if (bomb && (bomb->steps == 0 || bomb->steps > 127))
            throw CodecError("original_movement_bomb_count_invalid");
    };
    validate(roster.attached);
    std::set<std::uint8_t> slots{roster.mover};
    for (const auto& other : roster.others) {
        if (!slots.insert(other.slot).second) throw CodecError("original_movement_bomb_slot_duplicate");
        validate(other.bomb);
    }
}
OriginalBombPrediction predict_original_bombs(const OriginalBombRoster& roster, const OriginalRouteTrace& route) {
    validate_original_bombs(roster);
    OriginalBombPrediction result{roster,{},{},{}};
    auto& after = result.after;
    for (std::size_t index = 0; index < route.size(); ++index) {
        if (!after.attached) continue;
        if (after.countdown_enabled && --after.attached->steps == 0) {
            result.exploded_owner = after.attached->owner;
            after.attached.reset(); result.explosion_step = index+1;
            break;
        }
        OriginalBombOccupant* target = nullptr;
        for (auto& other : after.others) {
            if (!other.active || other.tile != route[index].tile || other.status1493 != -1 || other.status1489 != -1) continue;
            if (!target || other.slot < target->slot) target = &other;
        }
        if (target) {
            std::swap(after.attached,target->bomb);
            result.transfers.push_back({index+1,target->slot});
        }
    }
    return result;
}
}
