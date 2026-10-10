#pragma once

#include "codec.hpp"
#include <mutex>
#include <functional>

namespace richnet {
// 对局内四种独立资金；不自动把启动包的未知字段映射为任何一种资金。
struct RichonlineGameFunds {
    std::uint32_t cash;
    std::optional<std::uint32_t> deposit;
    std::uint32_t tickets;
    std::optional<std::uint32_t> reserve;
    bool operator==(const RichonlineGameFunds&) const = default;
};
struct RichonlineGameFundsSnapshot {
    RichonlineGameFunds funds;
    std::uint64_t revision;
    bool operator==(const RichonlineGameFundsSnapshot&) const = default;
};
struct RichonlineGameFundsDelta {
    std::int64_t cash,deposit,tickets,reserve;
};
struct RichonlineGameIncomeSnapshot {
    std::uint64_t earned_cash;
    std::uint64_t ledger_revision;
};
struct RichonlineGameFundsUpdate {
    std::uint8_t actor;
    RichonlineGameFundsSnapshot before;
    RichonlineGameFunds after;
};
class RichonlineGameLedger final {
public:
    explicit RichonlineGameLedger(std::vector<RichonlineGameFunds> initial);
    std::size_t actor_count() const noexcept { return balances_.size(); }
    RichonlineGameFundsSnapshot snapshot(std::uint8_t actor) const;
    // Local achievement policy: positive cash+deposit net increases, excluding
    // initial funds, internal transfers, tickets and account reserve. Rejects
    // unknown deposit balances rather than inventing a cash-only net income.
    std::uint64_t earned_cash(std::uint8_t actor) const;
    RichonlineGameIncomeSnapshot income_snapshot(std::uint8_t actor) const;
    RichonlineGameFundsSnapshot commit(std::uint8_t actor,const RichonlineGameFundsSnapshot& expected,
        const RichonlineGameFunds& updated);
    RichonlineGameFundsSnapshot adjust(std::uint8_t actor,const RichonlineGameFundsSnapshot& expected,
        const RichonlineGameFundsDelta& delta);
    // Runs authorize under the ledger lock after validating all balance/revision
    // bounds. It must not reenter this ledger. true commits without allocation;
    // false or an exception preserves funds. Intended for synchronous DB debit.
    std::optional<RichonlineGameFundsSnapshot> consume_reserve(std::uint8_t actor,std::uint32_t amount,
        const std::function<bool()>& authorize);
    // Validates every actor before invoking a synchronous transaction callback.
    // The callback must not reenter the ledger; false/throw leaves all actors
    // unchanged. A successful callback is followed by allocation-free commits.
    bool commit_batch(std::span<const RichonlineGameFundsUpdate> updates,
        const std::function<bool()>& authorize);
    // 同一角色可出现多次：后一步 before 必须衔接前一步的余额和版本。
    // 每步独立累计正收入，全部校验通过后一次提交；失败不保留任何中间资金状态。
    bool commit_sequence(std::span<const RichonlineGameFundsUpdate> updates,
        const std::function<bool()>& authorize);
private:
    bool commit_updates(std::span<const RichonlineGameFundsUpdate> updates,
        const std::function<bool()>& authorize,bool sequential);
    mutable std::mutex mutex_;
    std::vector<RichonlineGameFundsSnapshot> balances_;
    std::vector<std::uint64_t> earned_cash_;
};
}
