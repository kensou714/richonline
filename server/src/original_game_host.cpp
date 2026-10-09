#include "original_game_host.hpp"
#include <atomic>
#include <algorithm>
#include <set>
#include <utility>

namespace richnet {
struct OriginalGameHost::State {
    struct Member {
        std::uint64_t lease;
        std::uint32_t user;
        OriginalGamePlan plan;
        std::optional<GameAdmission> expected;
        bool admitted = false;
    };
    struct Match {
        std::recursive_mutex mutex;
        std::atomic<bool> closed{false}, ever_admitted{false};
        bool prepared = false, active = false;
        AdmissionClock::time_point deadline;
        std::vector<std::shared_ptr<Member>> members;
    };
    OriginalRoomGameProvider provider;
    OriginalGameEndpoint endpoint;
    std::chrono::milliseconds ttl;
    OriginalGameHostClock clock;
    GameLogSink log;
    OriginalGameRegistry registry;
    std::mutex mutex;
    std::map<std::uint64_t,std::shared_ptr<Match>> matches;
    bool stopped = false;
    std::uint64_t next_lease = 1, highest_generation = 0;

    State(OriginalRoomGameProvider p, OriginalGameEndpoint e, std::chrono::milliseconds duration, OriginalGameHostClock c, GameLogSink sink)
        : provider(std::move(p)), endpoint(e), ttl(duration), clock(std::move(c)), log(std::move(sink)) {}
    void report(std::string_view reason) noexcept {
        try { if (log) log("original_game_host_cleanup_failed reason="+std::string(reason)); } catch (...) {}
    }
    void close(const std::shared_ptr<Match>& match) {
        std::vector<std::function<void()>> cleanup;
        {
            const std::lock_guard lock(match->mutex);
            match->closed.store(true);
            for (const auto& member : match->members) {
                registry.cancel(member->lease);
                if (member->plan.disconnected) cleanup.push_back(std::exchange(member->plan.disconnected,{}));
                member->plan.map_ready = {}; member->plan.action = {}; member->plan.poll = {}; member->plan.closed_shop_context = {};
                member->plan.expired_shop_action = {};
            }
            match->members.clear();
        }
        for (const auto& action : cleanup) {
            try { action(); } catch (const std::exception& error) { report(error.what()); } catch (...) { report("unknown_exception"); }
        }
    }
    std::vector<std::shared_ptr<Match>> all_matches() {
        const std::lock_guard lock(mutex);
        std::vector<std::shared_ptr<Match>> result;
        for (const auto& [generation,match] : matches) { static_cast<void>(generation); result.push_back(match); }
        return result;
    }
    void expire(const std::shared_ptr<Match>& match, AdmissionClock::time_point now) {
        bool expired;
        {
            const std::lock_guard lock(match->mutex);
            expired = match->prepared && !match->active && !match->closed.load() && now >= match->deadline;
            if (expired) match->closed.store(true);
        }
        if (expired) close(match);
    }
    std::shared_ptr<Match> find(std::uint64_t generation) {
        const std::lock_guard lock(mutex);
        const auto found = matches.find(generation);
        if (found == matches.end()) throw CodecError("original_game_host_generation_missing");
        return found->second;
    }
    OriginalGamePlan wrap(const std::shared_ptr<Match>& match, const std::shared_ptr<Member>& member,
                          const std::shared_ptr<State>& self) {
        auto result = member->plan;
        const auto enter = [self,match] {
            self->expire(match,self->clock());
            if (match->closed.load()) throw CodecError("original_game_host_match_closed");
        };
        result.map_ready = [match,member,enter] {
            enter(); const std::lock_guard lock(match->mutex);
            if (match->closed.load()) throw CodecError("original_game_host_match_closed");
            const auto action = member->plan.map_ready; return action();
        };
        result.action = [match,member,enter](View plain) {
            enter(); const std::lock_guard lock(match->mutex);
            if (match->closed.load()) throw CodecError("original_game_host_match_closed");
            const auto action = member->plan.action; return action(plain);
        };
        if (member->plan.poll) result.poll = [match,member,enter] {
            enter(); const std::lock_guard lock(match->mutex);
            if (match->closed.load()) throw CodecError("original_game_host_match_closed");
            const auto action = member->plan.poll; return action();
        };
        if (member->plan.closed_shop_context) result.closed_shop_context = [match,member,enter] {
            enter(); const std::lock_guard lock(match->mutex);
            if (match->closed.load()) throw CodecError("original_game_host_match_closed");
            const auto action = member->plan.closed_shop_context; return action();
        };
        if (member->plan.expired_shop_action) result.expired_shop_action = [match,member,enter](View plain) {
            enter(); const std::lock_guard lock(match->mutex);
            if (match->closed.load()) throw CodecError("original_game_host_match_closed");
            const auto action = member->plan.expired_shop_action; return action(plain);
        };
        result.disconnected = [self,match] { self->close(match); };
        return result;
    }
    std::optional<OriginalGamePlan> consume(const GameAdmission& admission, std::shared_ptr<Match>& connection) {
        const auto now = clock();
        for (const auto& match : all_matches()) {
            expire(match,now);
            const std::lock_guard lock(match->mutex);
            if (match->closed.load() || !match->prepared) continue;
            for (const auto& member : match->members) {
                if (!member->expected || *member->expected != admission || member->admitted) continue;
                auto result = registry.consume(admission,now);
                if (!result) return {};
                member->admitted = true;
                match->ever_admitted.store(true);
                match->active = std::all_of(match->members.begin(),match->members.end(),[](const auto& item) { return item->admitted; });
                connection = match;
                return result;
            }
        }
        return {};
    }
};
OriginalGameHost::OriginalGameHost(OriginalRoomGameProvider provider, OriginalGameEndpoint endpoint,
    std::chrono::milliseconds ttl, OriginalGameHostClock clock, GameLogSink log) {
    if (!provider || !clock) throw CodecError("original_game_host_provider_required");
    if (ttl.count() <= 0) throw CodecError("original_game_host_ttl_invalid");
    if (endpoint.port == 0) throw CodecError("original_game_redirect_port_invalid");
    state_ = std::make_shared<State>(std::move(provider),endpoint,ttl,std::move(clock),std::move(log));
}
OriginalGameHost::~OriginalGameHost() {
    try { shutdown(); } catch (const std::exception& error) { state_->report(error.what()); } catch (...) { state_->report("shutdown_exception"); }
}
std::vector<OriginalRoomRedirect> OriginalGameHost::prepare(const OriginalRoomSnapshot& snapshot) {
    const auto self = state_;
    if (snapshot.generation == 0 || snapshot.players.empty() || snapshot.players.size() > 8)
        throw CodecError("original_game_host_snapshot_invalid");
    std::set<std::uint32_t> users, slots;
    for (const auto& player : snapshot.players)
        if (player.user_id > 32767 || player.slot >= 8 || !users.insert(player.user_id).second || !slots.insert(player.slot).second)
            throw CodecError("original_game_host_snapshot_invalid");
    if (!users.contains(snapshot.owner)) throw CodecError("original_game_host_snapshot_invalid");
    const auto now = self->clock();
    for (const auto& match : self->all_matches()) self->expire(match,now);
    auto match = std::make_shared<State::Match>();
    if (self->ttl > AdmissionClock::time_point::max()-now) throw CodecError("original_game_host_ttl_overflow");
    match->deadline = now+self->ttl;
    {
        const std::lock_guard lock(self->mutex);
        if (self->stopped) throw CodecError("original_game_host_stopped");
        if (snapshot.generation <= self->highest_generation) throw CodecError("original_game_host_generation_duplicate");
        self->matches.emplace(snapshot.generation,match);
        self->highest_generation = snapshot.generation;
    }
    try {
        auto plans = self->provider(snapshot);
        {
            const std::lock_guard lock(match->mutex);
            for (auto& item : plans) match->members.push_back(std::make_shared<State::Member>(State::Member{0,item.user_id,std::move(item.plan),{},false}));
            if (match->closed.load()) throw CodecError("original_game_host_match_closed");
            if (plans.size() != users.size()) throw CodecError("original_game_host_plan_membership_invalid");
            std::set<std::uint32_t> plan_users;
            for (const auto& member : match->members) {
                if (!users.contains(member->user) || !plan_users.insert(member->user).second) throw CodecError("original_game_host_plan_membership_invalid");
                validate_original_startup(member->plan.startup);
                if (!member->plan.map_ready || !member->plan.action) throw CodecError("original_game_strategy_required");
                const auto& init = member->plan.startup.init;
                if (init.players[init.local_slot].lobby_user_id != static_cast<std::int16_t>(member->user))
                    throw CodecError("original_game_startup_identity_mismatch");
            }
            const auto commit_now = self->clock();
            if (commit_now >= match->deadline) throw CodecError("original_game_host_prepare_expired");
            std::vector<OriginalRoomRedirect> redirects;
            for (const auto& member : match->members) {
                {
                    const std::lock_guard host_lock(self->mutex);
                    if (self->next_lease == 0) throw CodecError("original_game_host_lease_exhausted");
                    member->lease = self->next_lease++;
                }
                const OriginalAdmissionIdentity identity{snapshot.channel_id,snapshot.game_id,member->user};
                auto response = self->registry.prepare({member->lease,identity,self->endpoint,match->deadline},self->wrap(match,member,self),commit_now);
                const View bytes(response.payload);
                OriginalGameRedirect redirect{self->endpoint,read_le(bytes.subspan(6,4)),read_le(bytes.subspan(10,4)),read_le(bytes.subspan(14,4))};
                member->expected = original_expected_admission(identity,redirect);
                redirects.push_back({member->user,std::move(response)});
            }
            match->prepared = true;
            return redirects;
        }
    } catch (...) { self->close(match); throw; }
}
OriginalGameHostStatus OriginalGameHost::status(std::uint64_t generation) {
    const auto match = state_->find(generation);
    state_->expire(match,state_->clock());
    return {match->closed.load(),match->ever_admitted.load()};
}
bool OriginalGameHost::finished(std::uint64_t generation) { return status(generation).finished; }
void OriginalGameHost::cancel(std::uint64_t generation) { state_->close(state_->find(generation)); }
OriginalGameHostStatus OriginalGameHost::retire(std::uint64_t generation) {
    std::shared_ptr<State::Match> match;
    {
        const std::lock_guard lock(state_->mutex);
        const auto found = state_->matches.find(generation);
        if (found == state_->matches.end()) return {true,false};
        match = found->second;
    }
    state_->close(match);
    const OriginalGameHostStatus retired{true,match->ever_admitted.load()};
    const std::lock_guard lock(state_->mutex);
    state_->matches.erase(generation);
    return retired;
}
void OriginalGameHost::shutdown() {
    {
        const std::lock_guard lock(state_->mutex);
        state_->stopped = true;
    }
    for (const auto& match : state_->all_matches()) state_->close(match);
}
GameCallbacks OriginalGameHost::callbacks() {
    const auto self = state_;
    const auto connection = std::make_shared<std::shared_ptr<State::Match>>();
    auto callbacks = make_original_game_callbacks([self,connection](const GameAdmission& admission) { return self->consume(admission,*connection); },self->log);
    const auto guard = [self,connection] {
        if (!*connection) throw CodecError("original_game_host_connection_unbound");
        self->expire(*connection,self->clock());
        std::unique_lock lock((*connection)->mutex);
        if ((*connection)->closed.load()) throw CodecError("original_game_host_match_closed");
        return lock;
    };
    callbacks.admitted = [guard,action = std::move(callbacks.admitted)](const GameAdmission& admission) {
        const auto lock = guard(); return action(admission);
    };
    callbacks.message = [guard,action = std::move(callbacks.message)](const GameAdmission& admission,const Envelope299& envelope,View plain) {
        const auto lock = guard(); return action(admission,envelope,plain);
    };
    callbacks.poll = [guard,action = std::move(callbacks.poll)](const GameAdmission& admission) {
        const auto lock = guard(); return action(admission);
    };
    return callbacks;
}
}
