#pragma once

// 新版 BOSS 商店事件：维护当前点数、商品及等待期限，共用对局卡包。
#include "richonline_boss_cards.hpp"
#include "richonline_shop_catalog.hpp"
#include "richonline_game_payment.hpp"
#include "richonline_game_ledger.hpp"
#include <chrono>

namespace richnet {
class RichonlineBossShop final {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    using ChargeReserve = std::function<bool(std::uint32_t)>;
    class PreparedLanding {
    public:
        const RichonlineLandingResult& result() const noexcept { return result_; }
        const RichonlineShopStock& offers() const noexcept { return offers_; }
        const std::array<std::uint8_t,2>& opaque() const noexcept { return opaque_; }
        bool opens() const noexcept { return opens_; }
        std::uint32_t points() const noexcept { return points_; }
    private:
        PreparedLanding()=default;
        const RichonlineBossShop* owner_=nullptr;
        std::uint64_t generation_=0;
        std::optional<RichonlineGameFundsSnapshot> funds_;
        RichonlineChanceInventory inventory_{};
        RichonlineShopStock offers_{};
        std::array<std::uint8_t,2> opaque_{};
        RichonlineLandingResult result_{};
        std::uint32_t points_=0;
        bool opens_=false,committed_=false;
        friend class RichonlineBossShop;
    };
    // Live sessions pass their authoritative RNG here. An omitted chooser keeps
    // stable catalog order only for standalone deterministic compatibility callers.
    // 客户端未读取货架偏移 4/5 字节；这是显式兼容策略，没有已确认的游戏含义。
    RichonlineBossShop(const std::filesystem::path& root,RichonlineBossCards& cards,
        std::uint16_t game_id,Now now,std::array<std::uint8_t,2> stock_opaque = {0,255},
        RichonlineShopCatalog::Choose choose = {});
    RichonlineBossShop(const std::filesystem::path& root,RichonlineBossCards& cards,
        std::uint16_t game_id,std::shared_ptr<RichonlineGameLedger> ledger,Now now,
        std::array<std::uint8_t,2> stock_opaque = {0,255},RichonlineShopCatalog::Choose choose = {});
    // Atomic reserve charge supplied by the authoritative account/session owner.
    void enable_refresh(ChargeReserve charge) { charge_reserve_=std::move(charge); }
    void configure_refresh(const RichonlineGoldCharges& client_values,ChargeReserve charge);
    // Pure preflight: false means this shop does not handle the landing; invalid state throws.
    bool validate_landing(const RichonlineLandingContext& context) const;
    // 准备只抽货架；Lua回包校验后才开启等待、写货架和计时器。
    std::optional<PreparedLanding> prepare_landing(const RichonlineLandingContext&,std::uint32_t points) const;
    std::optional<PreparedLanding> prepare_landing(const RichonlineLandingContext&) const;
    RichonlineLandingResult commit_landing(PreparedLanding&);
    std::optional<RichonlineLandingResult> land(const RichonlineLandingContext& context,std::uint32_t points);
    std::optional<RichonlineLandingResult> land(const RichonlineLandingContext& context);
    // 调用方须先校验已认证角色、回合计数及当前待处理商店，再分派请求。
    RichonlineLandingResult handle(View request);
    std::optional<RichonlineLandingResult> poll();
    bool active() const noexcept { return deadline_.has_value(); }
    std::uint32_t points() const { return ledger_ ? ledger_->snapshot(0).funds.tickets : points_; }
    std::uint32_t price() const { return catalog_.price(1038); }
    std::uint32_t card_price(std::int16_t card) const { return catalog_.price(card); }
    bool card_has_price(std::int16_t card) const noexcept { return catalog_.can_sell(card); }
    const char* last_decision() const noexcept { return last_decision_; }
    std::optional<std::uint32_t> refresh_cost() const noexcept { return refresh_cost_; }
    const RichonlineShopStock& offers() const noexcept { return offers_; }
private:
    RichonlineBossCards& cards_;
    std::uint16_t game_id_;
    Now now_;
    std::array<std::uint8_t,2> stock_opaque_;
    RichonlineShopCatalog catalog_;
    RichonlineShopCatalog::Choose choose_;
    ChargeReserve charge_reserve_;
    RichonlineShopStock offers_{};
    std::optional<std::uint32_t> refresh_cost_;
    std::uint32_t points_ = 0;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    unsigned refreshes_ = 0;
    std::optional<Clock::time_point> deadline_;
    const char* last_decision_ = "not_open";
    std::uint64_t open_generation_=0;
    Bytes response(std::uint16_t opcode,std::int8_t index) const;
    Bytes stock(const RichonlineShopStock& offers,bool refreshed) const;
    RichonlineLandingResult close(const char* reason);
};
}
