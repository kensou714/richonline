#include "pending_game_admissions.hpp"

#include <utility>

namespace richnet {
void PendingGameAdmissions::prepare(PendingGameAdmission pending, AdmissionClock::time_point now) {
    if (capacity_ == 0) throw CodecError("game_admission_capacity_invalid");
    if (pending.lobby_owner == 0) throw CodecError("game_admission_owner_invalid");
    if (pending.expires_at <= now) throw CodecError("game_admission_expiry_invalid");
    static_cast<void>(encode_game_admission(pending.expected, pending.version));
    const std::lock_guard lock(mutex_);
    std::erase_if(pending_, [now](const auto& item) { return item.second.expires_at <= now; });
    for (const auto& [owner, existing] : pending_) {
        if (owner != pending.lobby_owner && existing.version == pending.version && existing.expected == pending.expected)
            throw CodecError("game_admission_descriptor_ambiguous");
    }
    if (!pending_.contains(pending.lobby_owner) && pending_.size() >= capacity_)
        throw CodecError("game_admission_capacity_reached");
    const auto owner = pending.lobby_owner;
    pending_.insert_or_assign(owner, std::move(pending));
}

std::optional<std::uint64_t> PendingGameAdmissions::consume(ClientVersion version, const GameAdmission& received,
                                                           AdmissionClock::time_point now) {
    // 版本和完整描述符同时匹配；在同一锁内删除，保证并发接入只能消费一次。
    const std::lock_guard lock(mutex_);
    std::erase_if(pending_, [now](const auto& item) { return item.second.expires_at <= now; });
    for (auto item = pending_.begin(); item != pending_.end(); ++item) {
        if (item->second.version == version && item->second.expected == received) {
            const auto owner = item->first;
            pending_.erase(item);
            return owner;
        }
    }
    return {};
}

void PendingGameAdmissions::cancel(std::uint64_t lobby_owner) {
    const std::lock_guard lock(mutex_);
    pending_.erase(lobby_owner);
}
}
