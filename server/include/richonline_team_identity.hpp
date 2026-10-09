#pragma once
#include <cstdint>

namespace richnet {
// Player profile wire7+44 is copied through record+88/snapshot+44 into actor+44.
// This is the existing emitted unassigned-team policy, not the lobby role ID.
inline constexpr std::int32_t richonline_unassigned_player_team=-2;
// NEW7F3F3D explicitly initializes mode3 synthetic actor+44 to1.
inline constexpr std::int32_t richonline_synthetic_boss_team=1;
}
