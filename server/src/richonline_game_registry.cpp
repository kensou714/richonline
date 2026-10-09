#include "richonline_game_registry.hpp"

#include <algorithm>
#include <atomic>
#include <set>
#include <utility>

namespace richnet {
struct RichonlineGameRegistry::State {
    using RoomIdentity = std::pair<std::uint32_t,std::uint32_t>;
    // 房间号只在频道内唯一；所有取消和查找都保留频道维度。
    struct Entry {
        RichonlineGamePlan plan;
        GameAdmission expected;
        RoomIdentity room;
        AdmissionClock::time_point expires_at;
        std::atomic_bool valid{true};
        bool active = false;
        std::uint64_t generation = 0;
        std::size_t generation_members = 0;
        std::mutex gate;
        bool cleaned = false;
        bool game_complete = false;
        std::atomic_bool lobby_confirmed{false};
        Entry(RichonlineGamePlan supplied, GameAdmission descriptor, RoomIdentity key)
            : plan(std::move(supplied)), expected(descriptor), room(key) {}
    };
    RichonlineGameProvider provider;
    std::uint32_t manager;
    std::chrono::milliseconds ttl;
    RichonlineGameClock clock;
    PendingGameAdmissions pending;
    std::mutex mutex;
    std::map<std::uint64_t, std::shared_ptr<Entry>> entries;
    bool stopped = false;
    std::uint64_t next_generation = 1;
    State(RichonlineGameProvider supply, std::uint32_t key, std::chrono::milliseconds timeout, RichonlineGameClock timer)
        : provider(std::move(supply)), manager(key), ttl(timeout), clock(std::move(timer)) {}
    std::vector<std::shared_ptr<Entry>> cancel(RoomIdentity room) {
        std::vector<std::shared_ptr<Entry>> cleanup;
        for (auto item = entries.begin(); item != entries.end();) {
            if (item->second->room != room) { ++item; continue; }
            item->second->valid = false;
            pending.cancel(item->first);
            cleanup.push_back(item->second);
            item = entries.erase(item);
        }
        return cleanup;
    }
    // Requires mutex. All members of this generation remain registered until the last exact 58 is confirmed.
    std::vector<std::shared_ptr<Entry>> retire_completed(const std::shared_ptr<Entry>& completed,
        std::vector<std::shared_ptr<Entry>> members) {
        if(members.size()!=completed->generation_members ||
            std::any_of(members.begin(),members.end(),[](const auto& entry) {return !entry->valid || !entry->lobby_confirmed;})) return {};
        for(const auto& entry:members) {
            const auto found=entries.find(entry->plan.connection);
            if(found==entries.end() || found->second!=entry) throw CodecError("richonline_game_retirement_identity_changed");
        }
        for(const auto& entry:members) {
            entry->valid=false; pending.cancel(entry->plan.connection); entries.erase(entry->plan.connection);
        }
        return members;
    }
    static void cleanup(const std::vector<std::shared_ptr<Entry>>& entries_to_close) {
        std::exception_ptr failure;
        for (const auto& entry : entries_to_close) {
            const std::lock_guard lock(entry->gate);
            if (entry->cleaned) continue;
            entry->cleaned = true;
            try { entry->plan.disconnected(); } catch (...) { if (!failure) failure = std::current_exception(); }
        }
        if (failure) std::rethrow_exception(failure);
    }
};
namespace {
void cleanup_plans(const std::vector<std::function<void()>>& callbacks) {
    std::exception_ptr failure;
    for (const auto& callback : callbacks) {
        try { callback(); } catch (...) { if (!failure) failure = std::current_exception(); }
    }
    if (failure) std::rethrow_exception(failure);
}
}
RichonlineGameRegistry::RichonlineGameRegistry(RichonlineGameProvider provider, std::uint32_t manager,
                                             std::chrono::milliseconds admission_ttl, RichonlineGameClock clock) {
    if (!provider || !clock || admission_ttl <= std::chrono::milliseconds::zero()) throw CodecError("richonline_game_registry_options_invalid");
    state_ = std::make_shared<State>(std::move(provider), manager, admission_ttl, std::move(clock));
}

std::vector<RichonlineRoomDispatch> RichonlineGameRegistry::prepare(const RichonlineRoomSnapshot& room) {
    if (room.description.extension.size() != 88) throw CodecError("richonline_game_room_extension_must_be_88");
    if (room.participants.empty() || room.participants.size() > 4) throw CodecError("richonline_game_room_participants_invalid");
    std::set<std::uint64_t> connections;
    std::set<std::uint32_t> actors, slots;
    for (const auto& peer : room.participants) {
        if (!peer.ready || peer.connection == 0 || peer.actor == 0 || peer.slot > 3 || !connections.insert(peer.connection).second ||
            !actors.insert(peer.actor).second || !slots.insert(peer.slot).second) throw CodecError("richonline_game_room_participants_invalid");
    }
    {
        const std::lock_guard lock(state_->mutex);
        if(state_->stopped) throw CodecError("richonline_game_registry_stopped");
        for(const auto& peer:room.participants)
            if(state_->entries.contains(peer.connection)) throw CodecError("richonline_game_plan_already_registered");
    }
    auto plans = state_->provider(room);
    std::vector<std::function<void()>> failed_plan_cleanup;
    for (const auto& plan : plans) if (plan.disconnected) failed_plan_cleanup.push_back(plan.disconnected);
    try {
    if (plans.size() != room.participants.size()) throw CodecError("richonline_game_plan_membership_mismatch");
    std::vector<std::shared_ptr<State::Entry>> entries;
    std::vector<RichonlineRoomDispatch> redirects;
    for (auto& plan : plans) {
        const auto peer = std::find_if(room.participants.begin(), room.participants.end(), [&](const auto& member) {
            return member.connection == plan.connection && member.actor == plan.actor;
        });
        if (peer == room.participants.end() || connections.erase(plan.connection) != 1)
            throw CodecError("richonline_game_plan_membership_mismatch");
        if (!plan.admitted || !plan.message || !plan.disconnected) throw CodecError("richonline_game_plan_callbacks_missing");
        redirects.push_back({plan.connection, encode_richonline_game_redirect(plan.redirect)});
        auto expected = richonline_expected_admission({room.channel, room.key, plan.actor}, plan.redirect);
        entries.push_back(std::make_shared<State::Entry>(std::move(plan), expected, State::RoomIdentity{room.channel,room.key}));
    }
    const std::lock_guard lock(state_->mutex);
    if (state_->stopped) throw CodecError("richonline_game_registry_stopped");
    for (const auto& entry : entries)
        if (state_->entries.contains(entry->plan.connection)) throw CodecError("richonline_game_plan_already_registered");
    const auto now = state_->clock();
    const auto generation=state_->next_generation++;
    try {
        for (const auto& entry : entries) {
            entry->generation=generation;
            entry->generation_members=entries.size();
            entry->expires_at = now + state_->ttl;
            state_->pending.prepare({entry->plan.connection, ClientVersion::richonline, entry->expected, now + state_->ttl}, now);
            state_->entries.emplace(entry->plan.connection, entry);
        }
    } catch (...) {
        for (const auto& entry : entries) {
            state_->pending.cancel(entry->plan.connection);
            state_->entries.erase(entry->plan.connection);
            entry->valid = false;
        }
        throw;
    }
    return redirects;
    } catch (...) {
        const auto failure = std::current_exception();
        cleanup_plans(failed_plan_cleanup);
        std::rethrow_exception(failure);
    }
}

void RichonlineGameRegistry::cancel_room(std::uint32_t room_key) {
    cancel_room(state_->manager,room_key);
}
bool RichonlineGameRegistry::has_room(std::uint32_t room_key) {
    return has_room(state_->manager,room_key);
}
void RichonlineGameRegistry::cancel_room(std::uint32_t channel,std::uint32_t room_key) {
    // 先在注册表锁内失效，再在锁外执行清理；业务回调由各条目的 gate 串行保护。
    std::vector<std::shared_ptr<State::Entry>> cleanup;
    { const std::lock_guard lock(state_->mutex); cleanup = state_->cancel({channel,room_key}); }
    State::cleanup(cleanup);
}
bool RichonlineGameRegistry::has_room(std::uint32_t channel,std::uint32_t room_key) {
    std::vector<std::shared_ptr<State::Entry>> cleanup;
    bool present = false;
    {
        const std::lock_guard lock(state_->mutex);
        const auto now = state_->clock();
        for (const auto& item : state_->entries) {
            const auto& entry = *item.second;
            if (entry.room != State::RoomIdentity{channel,room_key}) continue;
            present = true;
            if (!entry.active && entry.expires_at <= now) { cleanup = state_->cancel({channel,room_key}); present = false; break; }
        }
    }
    State::cleanup(cleanup);
    return present;
}
bool RichonlineGameRegistry::completed_room(std::uint32_t channel,std::uint32_t room_key) {
    std::vector<std::shared_ptr<State::Entry>> entries;
    {
        const std::lock_guard lock(state_->mutex);
        for(const auto& [connection,entry]:state_->entries) {
            static_cast<void>(connection);
            if(entry->room==State::RoomIdentity{channel,room_key} && entry->valid) entries.push_back(entry);
        }
    }
    if(entries.empty()) return false;
    for(const auto& entry:entries) {
        const std::lock_guard gate(entry->gate);
        if(!entry->valid) return false;
        if(!entry->game_complete) {
            if(!entry->plan.game_finished || !entry->plan.game_finished()) return false;
            entry->game_complete=true;
        }
    }
    return true;
}
bool RichonlineGameRegistry::notify_lobby_sent(std::uint64_t lobby_connection,const Frame& frame) {
    std::shared_ptr<State::Entry> entry;
    std::vector<std::shared_ptr<State::Entry>> members;
    {
        const std::lock_guard lock(state_->mutex);
        const auto found=state_->entries.find(lobby_connection);
        if(found==state_->entries.end() || !found->second->valid) return false;
        entry=found->second;
        // Prepare the full retirement snapshot before the durable observer can commit anything.
        for(const auto& [connection,member]:state_->entries) {
            static_cast<void>(connection);
            if(member->room==entry->room && member->generation==entry->generation) members.push_back(member);
        }
    }
    {
        const std::lock_guard gate(entry->gate);
        if(!entry->valid || entry->lobby_confirmed || frame.wire_type!=58 || !entry->plan.lobby_sent ||
            !entry->plan.game_finished || !entry->plan.game_finished()) return false;
        entry->game_complete=true;
        entry->plan.lobby_sent(frame);
        // The root outbox observer checks exact bytes. A wrong/partial frame leaves next=lobby and cannot retire.
        if(entry->plan.game_finished()) return false;
        entry->lobby_confirmed=true;
    }
    std::vector<std::shared_ptr<State::Entry>> retired;
    {
        const std::lock_guard lock(state_->mutex);
        const auto found=state_->entries.find(lobby_connection);
        if(found!=state_->entries.end() && found->second==entry) retired=state_->retire_completed(entry,std::move(members));
    }
    State::cleanup(retired);
    // The independent durable intent survives retirement. Run outside the
    // entry gate so the hook may stage/send a lobby refresh without reentrancy.
    if(entry->plan.profile_refresh_ready)entry->plan.profile_refresh_ready();
    return true;
}
void RichonlineGameRegistry::shutdown() {
    std::vector<std::shared_ptr<State::Entry>> cleanup;
    {
        const std::lock_guard lock(state_->mutex);
        state_->stopped = true;
        while (!state_->entries.empty()) {
            auto room = state_->cancel(state_->entries.begin()->second->room);
            cleanup.insert(cleanup.end(), room.begin(), room.end());
        }
    }
    State::cleanup(cleanup);
}

GameCallbacks RichonlineGameRegistry::callbacks() {
    const auto state = state_;
    const auto authorized = std::make_shared<std::shared_ptr<State::Entry>>();
    GameCallbacks result;
    result.authorize_admission = [state, authorized](const GameAdmission& admission) {
        const std::lock_guard lock(state->mutex);
        if (*authorized) return false;
        const auto owner = state->pending.consume(ClientVersion::richonline, admission, state->clock());
        if (!owner) return false;
        const auto found = state->entries.find(*owner);
        if (found == state->entries.end() || !found->second->valid || found->second->active) return false;
        *authorized = found->second;
        (*authorized)->active = true;
        return true;
    };
    result.admitted = [state, authorized](const GameAdmission& admission) {
        std::shared_ptr<State::Entry> entry;
        {
            const std::lock_guard lock(state->mutex);
            if (!*authorized || !(*authorized)->valid || (*authorized)->expected != admission)
                throw CodecError("richonline_game_plan_cancelled");
            entry = *authorized;
        }
        const std::lock_guard gate(entry->gate);
        if (!entry->valid) throw CodecError("richonline_game_plan_cancelled");
        return entry->plan.admitted();
    };
    result.message = [state, authorized](const GameAdmission& admission, const Envelope299& envelope, View plain) {
        std::shared_ptr<State::Entry> entry;
        {
            const std::lock_guard lock(state->mutex);
            if (!*authorized || !(*authorized)->valid || (*authorized)->expected != admission)
                throw CodecError("richonline_game_plan_cancelled");
            entry = *authorized;
        }
        const std::lock_guard gate(entry->gate);
        if (!entry->valid) throw CodecError("richonline_game_plan_cancelled");
        return entry->plan.message(envelope, plain);
    };
    result.disconnected = [state, authorized](const GameAdmission&) {
        std::shared_ptr<State::Entry> entry;
        {
            const std::lock_guard lock(state->mutex);
            if(*authorized && (*authorized)->valid) entry=*authorized;
        }
        if(!entry) return;
        {
            const std::lock_guard gate(entry->gate);
            if(!entry->valid) return;
            // Completed/delivering results keep their original lobby binding across game-socket close.
            const bool preserve=entry->game_complete ||
                (entry->plan.terminal_pending && entry->plan.terminal_pending()) ||
                (entry->plan.game_finished && entry->plan.game_finished());
            if(preserve) {
                if(!entry->cleaned) {
                    entry->cleaned=true;
                    entry->plan.disconnected();
                }
                return;
            }
        }
        std::vector<std::shared_ptr<State::Entry>> cleanup;
        {
            const std::lock_guard lock(state->mutex);
            // An old transport may close after its generation was replaced. Never cancel the new round.
            const auto found=state->entries.find(entry->plan.connection);
            if (entry->valid && found!=state->entries.end() && found->second==entry) cleanup = state->cancel(entry->room);
        }
        State::cleanup(cleanup);
    };
    result.poll = [state, authorized](const GameAdmission& admission) {
        std::shared_ptr<State::Entry> entry;
        {
            const std::lock_guard lock(state->mutex);
            if (!*authorized || !(*authorized)->valid || (*authorized)->expected != admission)
                throw CodecError("richonline_game_plan_cancelled");
            entry = *authorized;
        }
        const std::lock_guard gate(entry->gate);
        if (!entry->valid) throw CodecError("richonline_game_plan_cancelled");
        return entry->plan.poll ? entry->plan.poll() : std::vector<Frame>{};
    };
    result.sent = [state, authorized](const GameAdmission& admission,const Frame& frame) {
        std::shared_ptr<State::Entry> entry;
        {
            const std::lock_guard lock(state->mutex);
            if (!*authorized || !(*authorized)->valid || (*authorized)->expected != admission)
                throw CodecError("richonline_game_plan_cancelled");
            entry = *authorized;
        }
        const std::lock_guard gate(entry->gate);
        if (!entry->valid) throw CodecError("richonline_game_plan_cancelled");
        if (entry->plan.sent) entry->plan.sent(frame);
    };
    result.sent_enabled = [state, authorized](const GameAdmission& admission) {
        const std::lock_guard lock(state->mutex);
        return *authorized && (*authorized)->valid && (*authorized)->expected==admission &&
            static_cast<bool>((*authorized)->plan.sent);
    };
    return result;
}
}
