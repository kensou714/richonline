#include "original_game_startup.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <utility>
#include <memory>

namespace richnet {
namespace {
struct Session {
    OriginalGameAdmissionProvider provider;
    GameLogSink log;
    std::optional<OriginalGamePlan> plan;
    bool ready = false;
    std::uint16_t context = 0;

    ~Session() { release(); }
    void release() noexcept {
        if (!plan) return;
        auto finished = std::exchange(plan,{});
        try { if (finished->disconnected) finished->disconnected(); }
        catch (...) {
            try { if (log) log("original_game_cleanup_failed"); } catch (...) {}
        }
    }
    Frame frame(View plain) {
        Bytes filler(plain.size()+2);
        if (BCryptGenRandom(nullptr,filler.data(),static_cast<ULONG>(filler.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            throw CodecError("original_game_random_failed");
        const auto result = original_board_frame(plain,plan->startup.envelope,filler);
        if (log) log("original_game_sent opcode=" + std::to_string(read_le(plain.first(2))) +
            " plain_bytes=" + std::to_string(plain.size()));
        return result;
    }
    std::vector<Frame> output(const std::vector<Bytes>& messages) {
        std::vector<Frame> responses;
        auto next_context = context;
        for (const auto& plain : messages) {
            if (plain.size() < 4 || read_le(View(plain).subspan(2,2)) != plan->startup.init.gmsv_id)
                throw CodecError("original_game_response_instance_mismatch");
            const auto opcode = read_le(View(plain).first(2));
            if (opcode == 0x4000) throw CodecError("original_game_duplicate_initialization");
            if (opcode == 0x4004) {
                const auto required = 12 + 12*plan->startup.init.players.size();
                if (plain.size() < required) throw CodecError("original_game_snapshot_truncated");
                if (read_le(View(plain).subspan(8,4)) == 0) throw CodecError("original_board_scale_invalid");
                next_context = static_cast<std::uint16_t>(read_le(View(plain).subspan(4,4)) & 0xffffU);
            }
            if (opcode == 0x4010) {
                if (plain.size() < 7) throw CodecError("original_game_turn_truncated");
                if (plain[4] >= plan->startup.init.players.size() || plain[5] >= plan->startup.init.players.size())
                    throw CodecError("original_game_turn_slot_invalid");
                if (plain[6] == 0) next_context = static_cast<std::uint16_t>((next_context+1U) & 0xffffU);
            }
            responses.push_back(frame(plain));
        }
        context = next_context;
        return responses;
    }
    bool authorize(const GameAdmission& admission) {
        if (plan) throw CodecError("original_game_duplicate_authorization");
        auto proposed = provider(admission);
        if (!proposed) return false;
        plan = std::move(proposed);
        try {
            validate_original_startup(plan->startup);
            if (!plan->map_ready || !plan->action) throw CodecError("original_game_strategy_required");
            const auto self = plan->startup.init.players.at(plan->startup.init.local_slot).lobby_user_id;
            if (self < 0 || static_cast<std::uint32_t>(self) != admission.id2)
                throw CodecError("original_game_startup_identity_mismatch");
            context = static_cast<std::uint16_t>(plan->startup.snapshot.context & 0xffffU);
        } catch (...) { release(); throw; }
        return true;
    }
    std::vector<Frame> received(const Envelope299& envelope, View plain) {
        if (!plan) throw CodecError("original_game_startup_missing");
        if (envelope.inner_type != 0 || envelope.mode != -1 || plain.size() < 2)
            throw CodecError("original_game_client_envelope_unsupported");
        const auto opcode = read_le(plain.first(2));
        if (log) log("original_game_received opcode=" + std::to_string(opcode) + " plain_bytes=" + std::to_string(plain.size()));
        if (opcode == 0 || opcode == 1 || opcode == 2 || opcode == 10) {
            if (plain.size() != 2) throw CodecError("original_game_signal_length_invalid");
            if (opcode == 1) return {};
            if (opcode == 0) {
                if (ready) return {};
                auto replies = output({encode_original_board_snapshot(plan->startup.snapshot)});
                const auto opening = output(plan->map_ready());
                replies.insert(replies.end(),opening.begin(),opening.end());
                ready = true;
                return replies;
            }
            if (!ready) throw CodecError("original_game_action_before_map_ready");
            if (opcode == 10) throw CodecError("original_game_leave_requested");
            return output(plan->action(plain));
        }
        if (!ready) throw CodecError("original_game_action_before_map_ready");
        if (plain.size() < 4) throw CodecError("original_game_action_context_missing");
        if (plan->expired_shop_action && plan->expired_shop_action(plain)) {
            if (log) log("original_game_ignored_expired_shop_action opcode="+std::to_string(opcode)+
                " context="+std::to_string(read_le(plain.subspan(2,2))));
            return {};
        }
        if (opcode == 48 && plain.size() == 6 && plain[4] == 0xff && plan->closed_shop_context) {
            const auto closed = plan->closed_shop_context();
            if (closed && read_le(plain.subspan(2,2)) == *closed) {
                if (log) log("original_game_ignored_closed_shop_exit context=" + std::to_string(*closed));
                return {};
            }
        }
        if (read_le(plain.subspan(2,2)) != context) throw CodecError("original_game_action_context_mismatch");
        return output(plan->action(plain));
    }
};
}
GameCallbacks make_original_game_callbacks(OriginalGameAdmissionProvider provider, GameLogSink log) {
    if (!provider) throw CodecError("original_game_admission_provider_required");
    auto session = std::make_shared<Session>();
    session->provider = std::move(provider);
    session->log = std::move(log);
    return {
        [session](const GameAdmission& admission) { return session->authorize(admission); },
        [session](const GameAdmission&) { return std::vector<Frame>{session->frame(encode_original_board_init(session->plan->startup.init))}; },
        [session](const GameAdmission&,const Envelope299& envelope,View plain) { return session->received(envelope,plain); },
        [session](const GameAdmission&) { session->release(); },
        [session](const GameAdmission&) {
            if (!session->ready || !session->plan || !session->plan->poll) return std::vector<Frame>{};
            return session->output(session->plan->poll());
        }
    };
}
}
