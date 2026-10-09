#pragma once
#include "richonline_actor_status.hpp"
#include <map>
#include <random>

namespace richnet {
struct RichonlineGroundObject {
    std::int8_t npc;
    // 401C passes these bytes to the map record; meaning depends on NPC kind.
    std::uint8_t byte7,byte8;
    bool operator==(const RichonlineGroundObject&) const = default;
};
using RichonlineGroundMap=std::map<std::int16_t,RichonlineGroundObject>;
struct RichonlineGroundSnapshot {
    RichonlineGroundMap objects;
    std::uint64_t revision;
    bool operator==(const RichonlineGroundSnapshot&) const = default;
};
// Owned by the room's serialized executor. Mines, bombs, gods and chests share
// the same occupancy map, so a spawn can never overwrite another object.
class RichonlineGroundObjects {
public:
    explicit RichonlineGroundObjects(std::vector<std::int16_t> verified_walkable);
    RichonlineGroundSnapshot snapshot() const;
    const std::vector<std::int16_t>& positions() const noexcept { return positions_; }
    class Prepared {
    public:
        const RichonlineGroundSnapshot& expected() const noexcept { return expected_; }
        const RichonlineGroundMap& after() const noexcept { return after_; }
    private:
        Prepared()=default;
        RichonlineGroundSnapshot expected_{};
        RichonlineGroundMap after_;
        bool committed_=false;
        friend class RichonlineGroundObjects;
    };
    Prepared prepare(const RichonlineGroundSnapshot&,const RichonlineGroundMap& after) const;
    bool matches(const Prepared&) const noexcept;
    // Allocations and validation happen in prepare; the serialized room can
    // combine this swap with its ledger/cards/property atomic commit.
    bool commit_prepared(Prepared&) noexcept;
    bool commit(const RichonlineGroundSnapshot&,const RichonlineGroundMap& after);
    void place(std::int16_t,RichonlineGroundObject);
    bool consume(std::int16_t,RichonlineGroundObject expected);
private:
    std::vector<std::int16_t> positions_;
    RichonlineGroundMap objects_;
    std::uint64_t revision_=0;
};
Bytes encode_richonline_npc_spawn401c(std::uint16_t game,std::int16_t position,RichonlineGroundObject);
struct RichonlineNpcSpawnPolicy {
    std::size_t initial_gods,initial_chests,minimum_objects,maximum_objects;
    std::uint64_t refresh_every_rounds;
    std::vector<std::int8_t> god_pool;
    std::uint8_t god_byte7,god_byte8,chest_byte7,chest_byte8;
    bool refresh_chests=true;
    // User policy, not an inferred original server random distribution.
    static RichonlineNpcSpawnPolicy user_requested(std::uint8_t god7,std::uint8_t god8,
        std::uint8_t chest7,std::uint8_t chest8);
};
struct RichonlineNpcSpawnResult {
    std::vector<Bytes> messages;
    std::size_t unmet_target=0;
    bool duplicate=false;
};
class RichonlineNpcSpawner {
public:
    RichonlineNpcSpawner(std::uint16_t game,RichonlineNpcSpawnPolicy,std::uint32_t seed);
    RichonlineNpcSpawnResult initialize(RichonlineGroundObjects&);
    // Invoke after a pickup/removal to maintain the minimum immediately.
    RichonlineNpcSpawnResult replenish_minimum(RichonlineGroundObjects&);
    // Identity counts COMPLETE rounds, starts at1, and must have no gaps.
    RichonlineNpcSpawnResult finish_round(RichonlineGroundObjects&,std::uint64_t identity);
private:
    std::uint16_t game_;
    RichonlineNpcSpawnPolicy policy_;
    std::mt19937 random_;
    bool initialized_=false;
    std::uint64_t last_round_=0;
};
struct RichonlinePossessionClock {
    std::optional<std::int8_t> npc;
    std::uint8_t turns=0;
    std::optional<std::uint64_t> last_actor_turn;
};
struct RichonlinePossessionTick {
    RichonlinePossessionClock clock;
    RichonlineActorStatus status;
    std::optional<std::int8_t> expired;
    bool duplicate;
};
// NEW local6050 handles expiry; this server mirror emits no network packet.
RichonlinePossessionTick tick_richonline_possession(const RichonlinePossessionClock&,
    const RichonlineActorStatus&,std::uint64_t active_actor_turn);
}
