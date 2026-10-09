#include "richonline_game_startup.hpp"
#include "richonline_game_end.hpp"
#include "diagnostic_log.hpp"

#include <utility>

namespace richnet {
namespace {
struct Startup {
    RichonlineStartupProvider provider;
    RichonlineFrameFiller filler;
    GameLogSink log;
    std::optional<RichonlineStartupPlan> plan;
    bool map_loaded = false;
    std::optional<RichonlineMapLoadPolicy::Clock::time_point> map_loading_deadline;
    std::uint16_t action_counter = 0;

    ~Startup() { release(); }
    void release() noexcept {
        map_loading_deadline.reset();
        map_loaded = false;
        if (!plan) return;
        auto completed = std::exchange(plan, {});
        try { if (completed->disconnected) completed->disconnected(); }
        catch (...) {
            try { if (log) log("richonline_game_cleanup_failed"); } catch (...) {}
        }
    }
    Frame frame(View plain) {
        const auto result = richonline_board_frame(plain, plan->envelope, filler(plain.size()+2));
        if (log) log("richonline_game_sent opcode=" + std::to_string(read_le(plain.first(2))) +
                     " plain_bytes=" + std::to_string(plain.size()));
        return result;
    }
    std::vector<Frame> output(const std::vector<Bytes>& messages) {
        // 回合计数必须随实际生成的快照和回合包推进，不能由任意客户端请求改写。
        std::vector<Frame> result;
        auto next_counter = action_counter;
        for (const auto& plain : messages) {
            if (plain.size() < 4 || read_le(View(plain).subspan(2,2)) != plan->init.game_server_id)
                throw CodecError("richonline_game_response_instance_mismatch");
            const auto opcode = read_le(View(plain).first(2));
            if (opcode == 0x4000) throw CodecError("richonline_game_duplicate_initialization");
            if (opcode == 0x4004) {
                if (plain.size() != 12+12*plan->init.participants.size())
                    throw CodecError("richonline_game_snapshot_slot_count_mismatch");
                next_counter = static_cast<std::uint16_t>(read_le(View(plain).subspan(4,4)) & 0xffffU);
            }
            if (opcode == 0x4010) {
                if (plain.size() < 7) throw CodecError("richonline_game_turn_truncated");
                if (plain[4] >= plan->init.participants.size()) throw CodecError("richonline_game_turn_slot_invalid");
                if (plain[6] == 0) next_counter = static_cast<std::uint16_t>((next_counter+1U) & 0xffffU);
            }
            result.push_back(frame(plain));
        }
        action_counter = next_counter;
        return result;
    }
    bool authorize(const GameAdmission& admission) {
        if (plan) throw CodecError("richonline_game_duplicate_authorization");
        auto proposed = provider(admission);
        if (!proposed) return false;
        plan = std::move(proposed);
        try {
            static_cast<void>(encode_richonline_board_init(plan->init));
            static_cast<void>(encode_richonline_board_snapshot(plan->snapshot));
            if (!plan->map_ready || !plan->action) throw CodecError("richonline_game_strategy_required");
            if (plan->map_loading && (!plan->map_loading->now ||
                plan->map_loading->timeout < std::chrono::milliseconds(1000) ||
                plan->map_loading->timeout > std::chrono::milliseconds(600000)))
                throw CodecError("richonline_map_load_policy_invalid");
            if (plan->init.game_server_id != plan->snapshot.game_server_id ||
                plan->init.participants.size() != plan->snapshot.slots.size())
                throw CodecError("richonline_game_snapshot_plan_mismatch");
            const auto local = plan->init.participants.at(plan->init.local_slot).lobby_identity;
            if (local < 0 || static_cast<std::uint32_t>(local) != admission.id2)
                throw CodecError("richonline_game_startup_identity_mismatch");
            action_counter = static_cast<std::uint16_t>(plan->snapshot.calendar_counter & 0xffffU);
        } catch (...) { release(); throw; }
        return true;
    }
    std::vector<Frame> admitted() {
        if (!plan) throw CodecError("richonline_game_plan_missing");
        if (plan->map_loading && !map_loaded && !map_loading_deadline) {
            map_loading_deadline = plan->map_loading->now() + plan->map_loading->timeout;
            if (log) log("richonline_map_load_wait timeout_ms=" +
                std::to_string(plan->map_loading->timeout.count()));
        }
        return {{1,{}},frame(encode_richonline_board_init(plan->init))};
    }
    std::vector<Frame> received(const Envelope299& envelope, View plain) {
        if (!plan) throw CodecError("richonline_game_plan_missing");
        if (plain.size() < 2) throw CodecError("richonline_game_message_short");
        const auto opcode = read_le(plain.first(2));
        if (log) log("richonline_game_received opcode=" + std::to_string(opcode) +
                     " plain_bytes=" + std::to_string(plain.size()));
        if (opcode == 0 || opcode == 1 || opcode == 2 || opcode == 10) {
            if (plain.size() != 2) throw CodecError("richonline_game_signal_length_invalid");
            if (opcode == 1) return {};
            if (opcode == 0) {
                // 地图加载完成信号可重复到达，但棋盘快照与开局回合只能发送一次。
                if (map_loaded) return {};
                auto messages = std::vector<Bytes>{encode_richonline_board_snapshot(plan->snapshot)};
                auto opening = plan->map_ready();
                messages.insert(messages.end(), std::make_move_iterator(opening.begin()), std::make_move_iterator(opening.end()));
                auto result = output(messages);
                map_loaded = true;
                map_loading_deadline.reset();
                return result;
            }
            if (opcode == 10) {
                validate_richonline_leave_request(plain);
                return output({richonline_leave_ack(plan->init.game_server_id)});
            }
        }
        if (!map_loaded) throw CodecError("richonline_game_action_before_map_ready");
        if (opcode != 2) {
            if (plain.size() < 4) throw CodecError("richonline_game_action_context_mismatch");
            if (read_le(plain.subspan(2,2)) != action_counter) {
                // 仅放行明确登记为已结束的操作；其他旧计数请求仍视为上下文错误。
                if (plan->retired_action && plan->retired_action(plain)) return {};
                throw CodecError("richonline_game_action_context_mismatch");
            }
        }
        return output(plan->action(envelope, plain));
    }
    std::vector<Frame> poll() {
        if (!plan) return {};
        if (!map_loaded) {
            if (map_loading_deadline && plan->map_loading->now() >= *map_loading_deadline)
                throw CodecError("richonline_map_load_timeout");
            return {};
        }
        if (!plan->poll) return {};
        return output(plan->poll());
    }
    void sent(const Frame& delivered) {
        if (!plan || !plan->sent || delivered.wire_type!=299) return;
        const auto envelope=decode_envelope(delivered,ClientVersion::richonline);
        const auto plain=decode_inner(envelope.encoded);
        plan->sent(plain);
    }
};
}
GameCallbacks make_richonline_game_callbacks(RichonlineStartupProvider provider,
                                             RichonlineFrameFiller filler, GameLogSink log) {
    if (!provider || !filler) throw CodecError("richonline_game_startup_provider_required");
    auto state = std::make_shared<Startup>();
    state->provider = std::move(provider);
    state->filler = std::move(filler);
    state->log = nonthrowing_diagnostic_log(std::move(log));
    return {
        [state](const GameAdmission& admission) { return state->authorize(admission); },
        [state](const GameAdmission&) { return state->admitted(); },
        [state](const GameAdmission&, const Envelope299& envelope, View plain) { return state->received(envelope, plain); },
        [state](const GameAdmission&) { state->release(); },
        [state](const GameAdmission&) { return state->poll(); },
        [state](const GameAdmission&,const Frame& delivered) { state->sent(delivered); },
        [state](const GameAdmission&) { return state->plan && static_cast<bool>(state->plan->sent); }
    };
}
}
