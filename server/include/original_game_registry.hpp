#pragma once

#include "original_game_redirect.hpp"
#include "original_game_startup.hpp"
#include "pending_game_admissions.hpp"

namespace richnet {
struct OriginalGameReservation {
    std::uint64_t owner;
    OriginalAdmissionIdentity identity;
    OriginalGameEndpoint endpoint;
    AdmissionClock::time_point expires_at;
};

class OriginalGameRegistry final {
public:
    explicit OriginalGameRegistry(std::size_t capacity = 32) : admissions_(capacity) {}
    Frame prepare(const OriginalGameReservation& reservation, OriginalGamePlan plan, AdmissionClock::time_point now);
    std::optional<OriginalGamePlan> consume(const GameAdmission& admission, AdmissionClock::time_point now);
    void cancel(std::uint64_t owner);
private:
    struct Pending { AdmissionClock::time_point expires_at; OriginalGamePlan plan; };
    std::mutex mutex_;
    PendingGameAdmissions admissions_;
    std::map<std::uint64_t, Pending> pending_;
    void expire(AdmissionClock::time_point now);
};
}
