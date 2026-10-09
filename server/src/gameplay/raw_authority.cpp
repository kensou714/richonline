#include "richonline_raw_authority.hpp"
#include "richonline_game_startup.hpp"
#include "richonline_timed_bomb.hpp"

#include <bit>
#include <stdexcept>
#include <utility>

namespace richnet {

RichonlineRawAuthority::RichonlineRawAuthority(std::uint8_t actor_count, std::uint16_t gmsv_id)
    : actor_count_(actor_count), gmsv_id_(gmsv_id) {
    if (actor_count_ == 0 || actor_count_ > actors_.size())
        throw CodecError("richonline_raw_actor_count_invalid");
}

void RichonlineRawAuthority::initialize_game() {
    if (game_initialized_) throw CodecError("richonline_raw_game_already_initialized");
    game_.scripted_event83830 = static_cast<std::int8_t>(-1);
    game_.scripted_event_position.reset();
    game_initialized_ = true;
}

void RichonlineRawAuthority::initialize_actor(std::uint8_t actor) {
    require_actor(actor);
    if (initialized_[actor]) throw CodecError("richonline_raw_actor_already_initialized");
    auto& state = actors_[actor];
    state.hotel1493 = static_cast<std::int8_t>(-1);
    state.hospital1494 = static_cast<std::int8_t>(-1);
    state.jail1495 = static_cast<std::int8_t>(-1);
    state.kidnapped1497 = static_cast<std::int8_t>(-1);
    state.movement_reporting552 = true;
    initialized_[actor] = true;
}

void RichonlineRawAuthority::invalidate_actor(std::uint8_t actor) {
    mutable_actor(actor) = {};
}

void RichonlineRawAuthority::invalidate_game() {
    if (!game_initialized_) throw CodecError("richonline_raw_game_unknown");
    game_ = {};
}

const RichonlineRawActorState& RichonlineRawAuthority::actor(std::uint8_t actor) const {
    require_actor(actor);
    if (!initialized_[actor]) throw CodecError("richonline_raw_actor_unknown");
    return actors_[actor];
}

void RichonlineRawAuthority::require_actor(std::uint8_t actor) const {
    if (actor >= actor_count_) throw CodecError("richonline_raw_actor_invalid");
}

RichonlineRawActorState& RichonlineRawAuthority::mutable_actor(std::uint8_t actor) {
    require_actor(actor);
    if (!initialized_[actor]) throw CodecError("richonline_raw_actor_unknown");
    return actors_[actor];
}

void RichonlineRawAuthority::apply_s2c4011_movement(std::uint8_t actor) {
    mutable_actor(actor).movement_reporting552 = true;
}

void RichonlineRawAuthority::begin_hotel_relocation(std::uint8_t actor) {
    mutable_actor(actor).movement_reporting552 = false;
}

void RichonlineRawAuthority::enter_hotel(std::uint8_t actor, std::int8_t days) {
    require_duration(days);
    mutable_actor(actor).hotel1493 = days;
}

void RichonlineRawAuthority::exit_hotel(std::uint8_t actor) {
    auto& state = mutable_actor(actor);
    state.hotel1493 = static_cast<std::int8_t>(-1);
    state.movement_reporting552 = false;
}

void RichonlineRawAuthority::enter_hospital(std::uint8_t actor, std::int8_t days) {
    require_duration(days);
    auto& state = mutable_actor(actor);
    state.hospital1494 = days;
    state.hotel1493 = static_cast<std::int8_t>(-1);
}

void RichonlineRawAuthority::exit_hospital(std::uint8_t actor) {
    auto& state = mutable_actor(actor);
    state.hospital1494 = static_cast<std::int8_t>(-1);
    state.movement_reporting552 = false;
}

void RichonlineRawAuthority::enter_jail(std::uint8_t actor, std::int8_t days) {
    require_duration(days);
    auto& state = mutable_actor(actor);
    state.jail1495 = days;
    state.hotel1493 = static_cast<std::int8_t>(-1);
}

void RichonlineRawAuthority::exit_jail(std::uint8_t actor) {
    auto& state = mutable_actor(actor);
    state.jail1495 = static_cast<std::int8_t>(-1);
    state.movement_reporting552 = false;
}

void RichonlineRawAuthority::enter_kidnapped(std::uint8_t actor, std::int8_t days) {
    require_duration(days);
    mutable_actor(actor).kidnapped1497 = days;
}

void RichonlineRawAuthority::exit_kidnapped(std::uint8_t actor) {
    mutable_actor(actor).kidnapped1497 = static_cast<std::int8_t>(-1);
}

void RichonlineRawAuthority::apply_s2c420c(std::uint16_t gmsv_id, std::int16_t position) {
    if (gmsv_id != gmsv_id_) throw CodecError("richonline_raw_gmsv_mismatch");
    if (position < 0) throw CodecError("richonline_raw_scripted_position_invalid");
    if (!game_.scripted_event83830)
        throw CodecError("richonline_raw_game_unknown");
    game_.scripted_event83830 = static_cast<std::int8_t>(2);
    game_.scripted_event_position = position;
}

void RichonlineRawAuthority::decrement(std::optional<std::int8_t>& value) {
    if (!value) throw CodecError("richonline_raw_state_unknown");
    if (*value > 0) --*value;
}

void RichonlineRawAuthority::require_duration(std::int8_t value) {
    if (value < 0) throw CodecError("richonline_raw_duration_invalid");
}

bool RichonlineRawAuthority::apply_verified_actor_timer_phase(std::uint8_t actor, std::uint64_t turn_id) {
    auto& state = mutable_actor(actor);
    const auto previous = actor_timer_ids_[actor];
    if (previous && turn_id < *previous) throw CodecError("richonline_raw_actor_phase_stale");
    if (previous == turn_id) return false;
    if (!state.hotel1493 || !state.hospital1494 || !state.jail1495 || !state.kidnapped1497)
        throw CodecError("richonline_raw_state_unknown");
    decrement(state.hotel1493);
    decrement(state.hospital1494);
    decrement(state.jail1495);
    decrement(state.kidnapped1497);
    actor_timer_ids_[actor] = turn_id;
    return true;
}

bool RichonlineRawAuthority::apply_verified_calendar_advance(std::uint64_t day_id) {
    if (!game_.scripted_event83830) throw CodecError("richonline_raw_game_unknown");
    if (calendar_id_ && day_id < *calendar_id_) throw CodecError("richonline_raw_calendar_phase_stale");
    if (calendar_id_ == day_id) return false;
    decrement(game_.scripted_event83830);
    calendar_id_ = day_id;
    return true;
}

RichonlineRawDecision RichonlineRawAuthority::timed_bomb_target(std::uint8_t actor) const {
    require_actor(actor);
    if (!initialized_[actor]) return {RichonlineRawCapability::actor_unknown};
    const auto& state = actors_[actor];
    if (!state.hotel1493 || !state.hospital1494 || !state.jail1495 || !state.kidnapped1497)
        return {RichonlineRawCapability::actor_unknown};
    if (*state.hotel1493 != -1 || *state.hospital1494 != -1 || *state.jail1495 != -1 ||
        *state.kidnapped1497 != -1)
        return {RichonlineRawCapability::actor_status_active};
    return {RichonlineRawCapability::allowed};
}

RichonlineRawDecision RichonlineRawAuthority::timed_bomb_countdown(std::uint8_t actor) const {
    require_actor(actor);
    if (!initialized_[actor] || !actors_[actor].movement_reporting552)
        return {RichonlineRawCapability::actor_unknown};
    if (!game_.scripted_event83830) return {RichonlineRawCapability::game_unknown};
    if (!*actors_[actor].movement_reporting552)
        return {RichonlineRawCapability::movement_reporting_disabled};
    if (*game_.scripted_event83830 != -1)
        return {RichonlineRawCapability::scripted_event_active};
    return {RichonlineRawCapability::allowed};
}

RichonlineRawDecision RichonlineRawAuthority::timed_bomb_transfer_target(std::uint8_t actor) const {
    require_actor(actor);
    if (!initialized_[actor]) return {RichonlineRawCapability::actor_unknown};
    const auto& state = actors_[actor];
    if (!state.hotel1493 || !state.kidnapped1497)
        return {RichonlineRawCapability::actor_unknown};
    if (*state.hotel1493 != -1 || *state.kidnapped1497 != -1)
        return {RichonlineRawCapability::actor_status_active};
    return {RichonlineRawCapability::allowed};
}

RichonlineTimedBombStepContext RichonlineRawAuthority::timed_bomb_step_context(
    std::uint8_t moving_actor,std::int16_t actual_position) const {
    const auto& moving=actor(moving_actor);
    if (actual_position<0) throw CodecError("richonline_raw_step_position_invalid");
    if (!moving.movement_reporting552) throw CodecError("richonline_raw_movement_unknown");
    if (!game_.scripted_event83830) throw CodecError("richonline_raw_game_unknown");
    RichonlineTimedBombEligibility raw{};
    for (std::uint8_t slot=0;slot<actor_count_;++slot) {
        const auto& state=actor(slot);
        if (!state.hotel1493 || !state.hospital1494 || !state.jail1495 || !state.kidnapped1497)
            throw CodecError("richonline_raw_state_unknown");
        raw[slot]=RichonlineTimedBombRawEligibility{*state.hotel1493,*state.hospital1494,
            *state.jail1495,*state.kidnapped1497};
    }
    return {moving_actor,actor_count_,actual_position,*moving.movement_reporting552,
        *game_.scripted_event83830!=-1,raw};
}

std::shared_ptr<RichonlineRawAuthority> attach_richonline_raw_authority(RichonlineStartupPlan& plan) {
    const auto count=plan.init.participants.size();
    if (count==0 || count>8) throw CodecError("richonline_raw_actor_count_invalid");
    const auto game=plan.init.game_server_id;
    auto authority=std::make_shared<RichonlineRawAuthority>(static_cast<std::uint8_t>(count),game);
    authority->initialize_game();
    for (std::uint8_t actor=0;actor<count;++actor) authority->initialize_actor(actor);
    plan.sent=[authority,game,current=std::optional<std::uint8_t>{},sent=std::move(plan.sent)](View plain) mutable {
        if (plain.size()<2) throw CodecError("richonline_raw_sent_prefix_invalid");
        const auto opcode=read_le(plain.first(2));
        if (opcode==0x4010 || opcode==0x4011 || opcode==0x420c) {
            if (plain.size()<4) throw CodecError("richonline_raw_sent_prefix_invalid");
            if (read_le(plain.subspan(2,2))!=game) throw CodecError("richonline_raw_gmsv_mismatch");
            if (opcode==0x4010) {
                if (plain.size()<8) throw CodecError("richonline_raw_sent_prefix_invalid");
                if (plain[4]>=authority->actor_count()) throw CodecError("richonline_raw_actor_invalid");
                current=plain[4];
            } else if (opcode==0x4011) {
                if (plain.size()<28) throw CodecError("richonline_raw_sent_prefix_invalid");
                if (!current) throw CodecError("richonline_raw_current_actor_unknown");
                authority->apply_s2c4011_movement(*current);
            } else {
                // 67C5E0 consumes this six-byte prefix. The complete NEW 420C
                // size remains unresolved, so this observer imposes no tail.
                if (plain.size()<6) throw CodecError("richonline_raw_sent_prefix_invalid");
                const auto position=std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(4,2))));
                authority->apply_s2c420c(game,position);
            }
        }
        if (sent) sent(plain);
    };
    plan.disconnected=[authority,close=std::move(plan.disconnected)] {
        authority->invalidate_game();
        for (std::uint8_t actor=0;actor<authority->actor_count();++actor) authority->invalidate_actor(actor);
        if (close) close();
    };
    return authority;
}

} // namespace richnet
