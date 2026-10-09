#pragma once
#include "original_game_registry.hpp"
#include "original_room_snapshot.hpp"
#include <memory>

namespace richnet {
using OriginalRoomGameProvider = std::function<std::vector<OriginalGamePlanForUser>(const OriginalRoomSnapshot&)>;
using OriginalGameHostClock = std::function<AdmissionClock::time_point()>;
struct OriginalGameHostStatus { bool finished, admitted; };
class OriginalGameHost final {
public:
    OriginalGameHost(OriginalRoomGameProvider provider, OriginalGameEndpoint endpoint, std::chrono::milliseconds ttl,
                     OriginalGameHostClock clock = [] { return AdmissionClock::now(); }, GameLogSink log = {});
    ~OriginalGameHost();
    OriginalGameHost(const OriginalGameHost&) = delete;
    OriginalGameHost& operator=(const OriginalGameHost&) = delete;
    std::vector<OriginalRoomRedirect> prepare(const OriginalRoomSnapshot& snapshot);
    bool finished(std::uint64_t generation);
    OriginalGameHostStatus status(std::uint64_t generation);
    void cancel(std::uint64_t generation);
    OriginalGameHostStatus retire(std::uint64_t generation);
    void shutdown();
    GameCallbacks callbacks();
private:
    struct State;
    std::shared_ptr<State> state_;
};
}
