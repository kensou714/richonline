#pragma once

#include "codec.hpp"
#include <chrono>
#include <functional>
#include <memory>

namespace richnet {
class LuaServer;
enum class RichonlineGameBankAction : std::uint16_t { deposit = 0, withdraw = 1, exit = 2 };
enum class RichonlineGameBankVisit { passing, landing };
enum class RichonlineGameBankContinuation { await_choice, resume_movement, continue_landing };
enum class RichonlineGameBankOutcome {
    opened, transferred, exited, timed_out, synthetic_exit,
    rejected_amount, insufficient_funds, destination_limit
};
struct RichonlineGameBankBalance {
    std::uint32_t cash, deposit;
    bool operator==(const RichonlineGameBankBalance&) const = default;
};
struct RichonlineGameBankPassRequest {
    std::uint16_t calendar_counter;
    std::int16_t position;
};
struct RichonlineGameBankRequest {
    std::uint16_t calendar_counter;
    RichonlineGameBankAction action;
    std::array<std::uint8_t,2> unassigned_padding;
    std::int32_t amount;
};
RichonlineGameBankPassRequest decode_richonline_game_bank_pass(View plain);
RichonlineGameBankRequest decode_richonline_game_bank_request(View plain);
struct RichonlineGameBankEntry {
    std::uint8_t actor_slot;
    std::int16_t position;
    std::uint16_t calendar_counter;
    RichonlineGameBankVisit visit;
    RichonlineGameBankBalance balance;
    bool synthetic_actor;
};
struct RichonlineGameBankWirePolicy {
    // 4018 的内部重排会读取八字节，末字节含义未明；402A 的 +6..7 未读取。
    std::uint8_t admission_padding;
    std::array<std::uint8_t,2> transaction_padding;
};
struct RichonlineGameBankResult {
    std::vector<Bytes> messages;
    RichonlineGameBankEntry entry;
    RichonlineGameBankBalance after;
    RichonlineGameBankContinuation continuation;
    RichonlineGameBankOutcome outcome;
};
class RichonlineGameBank final {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    RichonlineGameBank(std::uint16_t game_id,RichonlineGameBankWirePolicy policy,Now now,
        std::shared_ptr<LuaServer> script = {});
    // 调用者须先验证角色、地图银行格、访问资格及原移动路线；模块不拥有持久化余额。
    RichonlineGameBankResult begin(const RichonlineGameBankEntry& entry);
    RichonlineGameBankResult handle(View request);
    std::optional<RichonlineGameBankResult> poll();
    bool active() const noexcept { return pending_.has_value(); }
private:
    struct Pending { RichonlineGameBankEntry entry; Clock::time_point deadline; };
    std::uint16_t game_id_;
    RichonlineGameBankWirePolicy policy_;
    Now now_;
    std::shared_ptr<LuaServer> script_;
    std::optional<Pending> pending_;
    // 只准备结果；完整Lua决策与回包通过核心复核后，调用者才关闭等待。
    RichonlineGameBankResult transaction(const RichonlineGameBankEntry& entry,
        const RichonlineGameBankRequest& request,bool timed_out) const;
};
}
