#pragma once

#include "original_route.hpp"

namespace richnet {
struct OriginalNpcSpawn {
    std::int16_t tile;
    std::uint8_t kind;
    bool operator==(const OriginalNpcSpawn&) const = default;
};
struct OriginalNpcSpawnInput {
    const std::map<std::int16_t,std::int32_t>& objects;
    std::span<const std::int16_t> occupied_tiles;
};
struct OriginalNpcSpawnResult {
    std::vector<OriginalNpcSpawn> spawned;
    std::uint8_t missing_minimum;
    bool space_exhausted;
};
class OriginalNpcSpawner final {
public:
    explicit OriginalNpcSpawner(std::shared_ptr<const OriginalMapResources> map);
    OriginalNpcSpawnResult initial(std::uint32_t context, const OriginalNpcSpawnInput& input,
                                   const OriginalRouteRandom& random);
    // Local policy: each elapsed three-turn interval permits one spawn; skipped intervals coalesce.
    // Contexts must advance by less than 2^31, including unsigned wrap. Apply returned spawns before reuse.
    OriginalNpcSpawnResult advance(std::uint32_t context, const OriginalNpcSpawnInput& input,
                                   const OriginalRouteRandom& random);
    OriginalNpcSpawnResult refill(const OriginalNpcSpawnInput& input, const OriginalRouteRandom& random) const;
private:
    std::vector<std::int16_t> eligible_;
    std::optional<std::uint32_t> last_context_;
    std::uint64_t elapsed_ = 0;
    std::uint64_t processed_interval_ = 0;
    std::vector<std::int16_t> available(const OriginalNpcSpawnInput& input) const;
};
}
