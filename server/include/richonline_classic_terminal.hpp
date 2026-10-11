#pragma once

#include "richonline_terminal.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_result_delivery.hpp"
#include <memory>

namespace richnet {
class LuaServer;
struct RichonlineClassicTerminalContext {
    std::uint16_t game_id;
    std::uint32_t room_id;
    // 受信任的准入层按局内槽提供身份、固定操作键、奖励策略和已扣押金凭据。
    // 这里不从客户端认领角色，也不以BOSS关卡奖励代替经典局经济规则。
    std::vector<GameSettlementParticipant> participants;
    std::int8_t win_rank,loss_rank;
    RichonlineResultByte18Compatibility byte18;
    bool show_text_270;
    RichonlineResultDisplayPolicy display;
    std::shared_ptr<LuaServer> script;
    // 第一至第四名的客户端图片索引来自准入配置；不能用胜/负两张图替代完整名次。
    std::optional<std::array<std::int8_t,4>> asset_rank_images{};
};
struct RichonlineClassicAssets {
    std::uint32_t cash,deposit;
    std::uint64_t stocks,property;
};
// 全体结果原子持久化；每名真人独立确认实际发送的完整战绩表及大厅58。
// 不自动恢复断线前发送过但未记下游标的动画，避免重复播放400E。
class RichonlineClassicTerminal final {
public:
    RichonlineClassicTerminal(Storage&,RichonlineClassicTerminalContext,std::shared_ptr<const RichonlineGameLedger>);
    void validate_identity(std::uint16_t game,std::uint32_t room,std::size_t count,std::uint32_t pawn_gold,
        const RichonlineGameLedger*) const;
    void validate_last_survivor(std::span<const std::uint8_t> active) const;
    std::vector<Bytes> finish(std::span<const std::uint8_t> active,std::uint8_t newly_bankrupt);
    void validate_month_limit(std::span<const std::uint8_t> active) const;
    std::vector<Bytes> finish_month_limit(std::span<const std::uint8_t> active,
        std::span<const RichonlineClassicAssets>,const std::string& property_valuation_evidence);
    void sent(std::uint8_t recipient,View plain);
    bool game_finished(std::uint8_t recipient) const;
    void lobby_sent(std::uint8_t recipient,const Frame&);
    bool committed() const noexcept { return committed_; }
private:
    Storage& storage_;
    RichonlineClassicTerminalContext context_;
    std::shared_ptr<const RichonlineGameLedger> ledger_;
    std::vector<Bytes> messages_;
    std::vector<std::size_t> cursors_;
    std::vector<RichonlineResultDeliveryGate> display_;
    bool committed_=false,recovery_required_=false;
    std::vector<Bytes> commit_result(std::span<const GameOutcome>,std::span<const std::int8_t>,
        GameSettlementDelivery,const std::string& extra_evidence);
};
}
