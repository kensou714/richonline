#pragma once

#include "codec.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>

namespace richnet {

struct RichonlineStartupPlan;
struct RichonlineTimedBombStepContext;

// These fields mirror the signed bytes used by NEW RnClient. An empty value is
// deliberately different from -1: it means the server has no authoritative
// transition history for that actor yet.
struct RichonlineRawActorState {
    std::optional<std::int8_t> hotel1493;
    std::optional<std::int8_t> hospital1494;
    std::optional<std::int8_t> jail1495;
    std::optional<std::int8_t> kidnapped1497;
    std::optional<bool> movement_reporting552;
    bool operator==(const RichonlineRawActorState&) const = default;
};

struct RichonlineRawGameState {
    std::optional<std::int8_t> scripted_event83830;
    std::optional<std::int16_t> scripted_event_position;
};

enum class RichonlineRawCapability {
    allowed,
    actor_unknown,
    game_unknown,
    actor_status_active,
    movement_reporting_disabled,
    scripted_event_active,
};

struct RichonlineRawDecision {
    RichonlineRawCapability capability;
    bool allowed() const noexcept { return capability == RichonlineRawCapability::allowed; }
};

// Pure authority holder for the raw NEW fields used by timed-bomb targeting
// and countdown. It is intentionally independent from Turns/session/runtime.
// Callers must feed only verified protocol or map transitions.
class RichonlineRawAuthority final {
public:
    explicit RichonlineRawAuthority(std::uint8_t actor_count, std::uint16_t gmsv_id);

    std::uint8_t actor_count() const noexcept { return actor_count_; }
    void initialize_game();
    void initialize_actor(std::uint8_t actor);
    void invalidate_actor(std::uint8_t actor);
    void invalidate_game();

    const RichonlineRawActorState& actor(std::uint8_t actor) const;
    const RichonlineRawGameState& game() const noexcept { return game_; }

    // Verified client transitions. Values are signed raw bytes; no sentinel is
    // invented by this API. Hotel/hospital/jail exit animations disable
    // movement reporting during their synthetic relocations.
    void apply_s2c4011_movement(std::uint8_t actor);
    // Hotel animation6 disables reporting before its delayed entry setter.
    void begin_hotel_relocation(std::uint8_t actor);
    void enter_hotel(std::uint8_t actor, std::int8_t days);
    void exit_hotel(std::uint8_t actor);
    void enter_hospital(std::uint8_t actor, std::int8_t days);
    void exit_hospital(std::uint8_t actor);
    void enter_jail(std::uint8_t actor, std::int8_t days);
    // 卡牌事务先保存原始状态，所有回包准备成功后再提交，避免先扣卡后入狱失败。
    class PreparedJailEntry final {
    private:
        PreparedJailEntry()=default;
        const RichonlineRawAuthority* owner_=nullptr;
        std::uint8_t actor_=0;
        std::int8_t days_=0;
        RichonlineRawActorState before_{};
        bool committed_=false;
        friend class RichonlineRawAuthority;
    };
    PreparedJailEntry prepare_jail_entry(std::uint8_t actor,std::int8_t days) const;
    bool matches_jail_entry(const PreparedJailEntry&) const noexcept;
    bool commit_jail_entry(PreparedJailEntry&) noexcept;
    void exit_jail(std::uint8_t actor);
    void enter_kidnapped(std::uint8_t actor, std::int8_t days);
    void exit_kidnapped(std::uint8_t actor);
    void apply_s2c420c(std::uint16_t gmsv_id, std::int16_t position);

    // Separate clocks in7C0C50. The actor path is reached in its own turn;
    // the scripted-event path is reached only on an actual calendar advance.
    // The owner supplies monotonic phase ids. Exact duplicates return false;
    // older ids throw. The all-actor/day shortcut is deliberately unavailable.
    bool apply_verified_actor_timer_phase(std::uint8_t actor, std::uint64_t turn_id);
    bool apply_verified_calendar_advance(std::uint64_t day_id);

    RichonlineRawDecision timed_bomb_target(std::uint8_t actor) const;
    RichonlineRawDecision timed_bomb_transfer_target(std::uint8_t actor) const;
    RichonlineRawDecision timed_bomb_countdown(std::uint8_t actor) const;
    // Immutable projection for the serialized route owner. Unknown fields
    // reject before inventory or movement transactions can be prepared.
    RichonlineTimedBombStepContext timed_bomb_step_context(
        std::uint8_t moving_actor,std::int16_t actual_position) const;

private:
    void require_actor(std::uint8_t actor) const;
    RichonlineRawActorState& mutable_actor(std::uint8_t actor);
    static void decrement(std::optional<std::int8_t>& value);
    static void require_duration(std::int8_t value);

    std::uint8_t actor_count_;
    std::uint16_t gmsv_id_;
    std::array<RichonlineRawActorState, 8> actors_{};
    std::array<bool, 8> initialized_{};
    std::array<std::optional<std::uint64_t>, 8> actor_timer_ids_{};
    std::optional<std::uint64_t> calendar_id_;
    bool game_initialized_ = false;
    RichonlineRawGameState game_{};
};

// Owns one NEW client's constructor state per startup and composes its whole-
// frame sent/disconnect observers. It does not infer animation timer phases.
std::shared_ptr<RichonlineRawAuthority> attach_richonline_raw_authority(RichonlineStartupPlan& plan);

} // namespace richnet
