#include "original_npc_spawn.hpp"
#include <algorithm>
#include <set>

namespace richnet {
namespace {
constexpr std::array<std::uint8_t,7> gods{0,1,2,3,4,6,7};
constexpr std::array<std::uint8_t,8> replenishments{0,1,2,3,4,6,7,9};
std::uint8_t population(const OriginalNpcSpawnInput& input) {
    std::size_t count = 0;
    for (const auto& [tile,kind] : input.objects) {
        static_cast<void>(tile);
        if ((kind >= 0 && kind <= 7) || kind == 9 || kind == 32) ++count;
    }
    if (count > 5) throw CodecError("original_npc_population_exceeds_limit");
    return static_cast<std::uint8_t>(count);
}
std::size_t pick(const OriginalRouteRandom& random, std::size_t count) {
    if (!random) throw CodecError("original_npc_random_required");
    const auto chosen = random(static_cast<std::uint32_t>(count));
    if (chosen >= count) throw CodecError("original_npc_random_out_of_range");
    return chosen;
}
OriginalNpcSpawnResult replenish(std::vector<std::int16_t> candidates, std::uint8_t count,
    std::uint8_t requested, const OriginalRouteRandom& random) {
    OriginalNpcSpawnResult result{{},0,false};
    for (std::uint8_t i = 0; i < requested; ++i) {
        if (candidates.empty()) { result.space_exhausted = true; break; }
        const auto position = pick(random,candidates.size());
        const auto kind = replenishments[pick(random,replenishments.size())];
        result.spawned.push_back({candidates[position],kind});
        candidates.erase(candidates.begin()+static_cast<std::ptrdiff_t>(position));
    }
    const auto after = static_cast<std::size_t>(count)+result.spawned.size();
    result.missing_minimum = static_cast<std::uint8_t>(after < 2 ? 2-after : 0);
    return result;
}
}
OriginalNpcSpawner::OriginalNpcSpawner(std::shared_ptr<const OriginalMapResources> map) {
    if (!map) throw CodecError("original_npc_map_required");
    std::set<std::int16_t> seen;
    for (const auto& road : map->roads) {
        if (road.tile < 0 || road.property_id < -1 || !seen.insert(road.tile).second)
            throw CodecError("original_npc_road_invalid");
        if (road.property_id == -1) eligible_.push_back(road.tile);
    }
}
std::vector<std::int16_t> OriginalNpcSpawner::available(const OriginalNpcSpawnInput& input) const {
    std::vector<std::int16_t> candidates;
    for (const auto tile : eligible_)
        if (!input.objects.contains(tile) && std::find(input.occupied_tiles.begin(),input.occupied_tiles.end(),tile) == input.occupied_tiles.end())
            candidates.push_back(tile);
    return candidates;
}
OriginalNpcSpawnResult OriginalNpcSpawner::initial(std::uint32_t context, const OriginalNpcSpawnInput& input,
    const OriginalRouteRandom& random) {
    if (last_context_) throw CodecError("original_npc_already_initialized");
    if (population(input) != 0) throw CodecError("original_npc_initial_population_conflict");
    auto candidates = available(input);
    if (candidates.size() < 5) throw CodecError("original_npc_initial_space_insufficient");
    std::vector<std::uint8_t> choices(gods.begin(),gods.end());
    OriginalNpcSpawnResult result{{},0,false};
    for (unsigned i = 0; i < 5; ++i) {
        const auto position = pick(random,candidates.size());
        std::uint8_t kind = 9;
        if (i < 4) {
            const auto god = pick(random,choices.size());
            kind = choices[god];
            choices.erase(choices.begin()+static_cast<std::ptrdiff_t>(god));
        }
        result.spawned.push_back({candidates[position],kind});
        candidates.erase(candidates.begin()+static_cast<std::ptrdiff_t>(position));
    }
    last_context_ = context;
    return result;
}
OriginalNpcSpawnResult OriginalNpcSpawner::advance(std::uint32_t context, const OriginalNpcSpawnInput& input,
    const OriginalRouteRandom& random) {
    if (!last_context_) throw CodecError("original_npc_not_initialized");
    const auto count = population(input);
    const auto difference = context-*last_context_;
    if (difference > 0x7fffffffU) throw CodecError("original_npc_context_out_of_order");
    const auto next_elapsed = elapsed_+difference;
    const auto interval = next_elapsed/3;
    const auto requested = static_cast<std::uint8_t>(interval > processed_interval_ && count < 5 ? 1 : 0);
    auto result = replenish(available(input),count,requested,random);
    last_context_ = context;
    elapsed_ = next_elapsed;
    processed_interval_ = interval;
    return result;
}
OriginalNpcSpawnResult OriginalNpcSpawner::refill(const OriginalNpcSpawnInput& input, const OriginalRouteRandom& random) const {
    if (!last_context_) throw CodecError("original_npc_not_initialized");
    const auto count = population(input);
    return replenish(available(input),count,static_cast<std::uint8_t>(count < 2 ? 2-count : 0),random);
}
}
