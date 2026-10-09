#include "original_game_registry.hpp"

namespace richnet {
void OriginalGameRegistry::expire(AdmissionClock::time_point now) {
    for (auto item = pending_.begin(); item != pending_.end();) {
        if (item->second.expires_at > now) { ++item; continue; }
        admissions_.cancel(item->first);
        item = pending_.erase(item);
    }
}
Frame OriginalGameRegistry::prepare(const OriginalGameReservation& reservation, OriginalGamePlan plan,
    AdmissionClock::time_point now) {
    validate_original_startup(plan.startup);
    if (!plan.map_ready || !plan.action) throw CodecError("original_game_strategy_required");
    const auto self = plan.startup.init.players.at(plan.startup.init.local_slot).lobby_user_id;
    if (self < 0 || static_cast<std::uint32_t>(self) != reservation.identity.user_id)
        throw CodecError("original_game_startup_identity_mismatch");
    const auto redirect = original_redirect_with_random_tokens(reservation.endpoint);
    const auto expected = original_expected_admission(reservation.identity,redirect);
    const auto response = encode_original_game_redirect(redirect);
    const std::lock_guard lock(mutex_);
    expire(now);
    admissions_.prepare({reservation.owner,ClientVersion::legacy,expected,reservation.expires_at},now);
    try { pending_.insert_or_assign(reservation.owner,Pending{reservation.expires_at,std::move(plan)}); }
    catch (...) { admissions_.cancel(reservation.owner); pending_.erase(reservation.owner); throw; }
    return response;
}
std::optional<OriginalGamePlan> OriginalGameRegistry::consume(const GameAdmission& admission,
    AdmissionClock::time_point now) {
    const std::lock_guard lock(mutex_);
    expire(now);
    const auto owner = admissions_.consume(ClientVersion::legacy,admission,now);
    if (!owner) return {};
    auto node = pending_.extract(*owner);
    if (node.empty()) throw CodecError("original_game_reservation_missing");
    return std::move(node.mapped().plan);
}
void OriginalGameRegistry::cancel(std::uint64_t owner) {
    const std::lock_guard lock(mutex_);
    admissions_.cancel(owner);
    pending_.erase(owner);
}
}
