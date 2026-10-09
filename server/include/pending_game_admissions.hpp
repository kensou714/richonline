#pragma once

// 共享准入队列：按版本和完整描述匹配一次性凭据，使用单调时钟控制有效期。

#include "game_admission.hpp"

#include <chrono>
#include <map>
#include <mutex>

namespace richnet {

using AdmissionClock = std::chrono::steady_clock;
struct PendingGameAdmission {
    std::uint64_t lobby_owner;
    ClientVersion version;
    GameAdmission expected;
    AdmissionClock::time_point expires_at;
};

class PendingGameAdmissions final {
public:
    explicit PendingGameAdmissions(std::size_t capacity = 32) : capacity_(capacity) {}
    // 同一大厅所有者的新预留替换旧记录；拒绝不同所有者共用相同准入描述。
    void prepare(PendingGameAdmission pending, AdmissionClock::time_point now);
    // 匹配成功后在锁内移除记录，返回大厅所有者；过期或不匹配返回空值。
    std::optional<std::uint64_t> consume(ClientVersion version, const GameAdmission& received,
                                         AdmissionClock::time_point now);
    void cancel(std::uint64_t lobby_owner);
private:
    std::size_t capacity_;
    std::mutex mutex_;
    std::map<std::uint64_t, PendingGameAdmission> pending_;
};

}
