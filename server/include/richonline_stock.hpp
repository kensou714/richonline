#pragma once

// 局内股票：市场槽与Stock.kpd配置编号分开，持仓与资金共享会话串行化边界。
#include "richonline_game_ledger.hpp"
#include "richonline_chance.hpp"
#include "lua_server.hpp"
#include <memory>

namespace richnet {
class RichonlineBossCards;
struct RichonlineStockForcedSaleRequest {
    std::uint16_t calendar_counter,stock_slot;
    std::int8_t inventory_slot;
};
// 0097使用日历和主手牌槽；当前只支持已有主手牌库存，不接受未知分组。
RichonlineStockForcedSaleRequest decode_richonline_stock_forced_sale_request(View);
struct RichonlineStockSubscriptionRequest {
    std::uint16_t calendar_counter,stock_slot;
    std::int8_t inventory_slot;
    std::uint8_t target;
};
// 0096没有数量字段；数量不能从保留字节或客户端资金预览推导。
RichonlineStockSubscriptionRequest decode_richonline_stock_subscription_request(View);
enum class RichonlineStockAction { buy, sell };
struct RichonlineStockRequest {
    RichonlineStockAction action;
    std::uint16_t slot,quantity;
};
// 0200/0201的+2是股票槽，不能交给日历字段认证器。
RichonlineStockRequest decode_richonline_stock_request(View);
struct RichonlineStockQuote {
    std::int32_t configuration;
    std::uint32_t supply;
    float price;
    float change_percent;
};
struct RichonlineStockHolding {
    std::uint32_t quantity=0;
    float cost=0;
};
struct RichonlineStockIndex {
    float previous,current,factor;
};
// 4200/4201/4202/4203共用原始涨跌计算；中间使用double，最后按客户端写回float。
// 本函数不修饰涨跌停阈值，也不改变实际报价。
float richonline_stock_change_percent(float previous,float current);
class RichonlineStockMarket final {
public:
    // 报价必须来自已经同步给客户端的权威初始化；这里不猜测原服务器行情算法。
    RichonlineStockMarket(std::uint16_t game,std::shared_ptr<RichonlineGameLedger> ledger,
        std::vector<RichonlineStockQuote> quotes,float rise_limit,float fall_limit,RichonlineStockIndex index,
        std::shared_ptr<LuaServer> script = {});
    RichonlineStockMarket(const RichonlineStockMarket&)=delete;
    RichonlineStockMarket& operator=(const RichonlineStockMarket&)=delete;
    RichonlineStockMarket(RichonlineStockMarket&&)=delete;
    RichonlineStockMarket& operator=(RichonlineStockMarket&&)=delete;
    RichonlineStockHolding holding(std::uint8_t actor,std::uint16_t slot) const;
    RichonlineStockQuote quote(std::uint16_t slot) const;
    RichonlineStockIndex index() const noexcept {return index_;}
    void set_restricted(bool restricted);
    class QuoteUpdate final {
    public:
        // prepare不改变行情。仅在commit成功后按发送队列顺序广播一次。
        const Bytes& response() const noexcept {return response_;}
    private:
        QuoteUpdate()=default;
        const RichonlineStockMarket* owner_=nullptr;
        std::uint64_t revision_=0;
        std::vector<RichonlineStockQuote> quotes_;
        RichonlineStockIndex index_{};
        Bytes response_;
        friend class RichonlineStockMarket;
    };
    QuoteUpdate prepare_price(std::uint16_t slot,float price) const;
    // 4202的提示标志固定在+52，缺少的股票槽填零。必须提供全部本局股票的新价。
    QuoteUpdate prepare_market(std::span<const float> prices,float current_index,float factor,bool notify) const;
    bool commit(const QuoteUpdate&);
    // 单股更新的便捷入口，使用同一准备/提交逻辑；不推进移动或落点状态。
    Bytes change_price(std::uint16_t slot,float price);
    class Trade final {
    public:
        bool accepted() const noexcept {return accepted_;}
        const std::string& reason() const noexcept {return reason_;}
        // 拒绝交易不伪造4206或400B；接受交易的包只在commit成功后发送一次。
        const Bytes& response() const noexcept {return response_;}
    private:
        Trade()=default;
        const RichonlineStockMarket* owner_=nullptr;
        std::uint64_t revision_=0;
        bool accepted_=false;
        std::string reason_;
        Bytes response_;
        std::uint16_t slot_=0;
        RichonlineStockHolding holding_;
        std::uint32_t supply_=0;
        RichonlineGameFundsUpdate funds_{};
        friend class RichonlineStockMarket;
    };
    // actor来自已认证连接，不取当前走子者；动作上下文/在场资格由上层准入负责。
    Trade prepare(std::uint8_t actor,const RichonlineStockRequest&) const;
    // 同一计划不能提交两次；价格/限制/持仓/资金变化均使旧计划失效。
    bool commit(const Trade&);
    class ForcedSale final {
    public:
        bool accepted() const noexcept {return accepted_;}
        const std::string& reason() const noexcept {return reason_;}
        const Bytes& response() const noexcept {return response_;}
    private:
        ForcedSale()=default;
        const RichonlineStockMarket* owner_=nullptr;
        const RichonlineBossCards* cards_=nullptr;
        std::uint64_t revision_=0;
        bool accepted_=false;
        std::string reason_;
        Bytes response_;
        std::uint16_t slot_=0;
        std::uint32_t supply_=0;
        std::array<std::uint8_t,8> active_{};
        std::vector<RichonlineGameFundsUpdate> funds_;
        RichonlineChanceInventory source_inventory_{},remaining_inventory_{};
        friend class RichonlineStockMarket;
    };
    // 上层验证日历、当前操作者及手牌归属。active按原角色槽排列，不能压缩淘汰槽。
    // 卡牌直接按现价清仓，不应用普通买卖的涨跌停/闭市门；零持仓也消耗1124。
    ForcedSale prepare_forced_sale(std::uint8_t actor,const RichonlineStockForcedSaleRequest&,
        std::span<const std::uint8_t> active,const RichonlineBossCards& cards) const;
    // 会话串行化边界内重新核验活动角色、手牌、市场和账本，然后一次提交扣卡/清仓/资金。
    bool commit(const ForcedSale&,std::span<const std::uint8_t> active,RichonlineBossCards& cards);
    class Subscription final {
    public:
        bool accepted() const noexcept {return accepted_;}
        bool consumes_card() const noexcept {return accepted_ && quantity_!=0;}
        const std::string& reason() const noexcept {return reason_;}
        const Bytes& response() const noexcept {return response_;}
    private:
        Subscription()=default;
        const RichonlineStockMarket* owner_=nullptr;
        const RichonlineBossCards* cards_=nullptr;
        std::uint64_t revision_=0;
        bool accepted_=false;
        std::string reason_;
        Bytes response_;
        std::uint16_t slot_=0;
        std::uint32_t quantity_=0;
        std::array<std::uint8_t,8> active_{};
        std::array<RichonlineGameFundsUpdate,2> funds_{};
        std::array<RichonlineStockHolding,2> holdings_{};
        RichonlineChanceInventory source_inventory_{},remaining_inventory_{};
        friend class RichonlineStockMarket;
    };
    // quantity由后续服务端数量策略明确提供，不从0096解码，也不猜测必须买光。
    // 仅目标确实无持仓时允许quantity=0，此分支发送40E6恢复但不扣卡。
    Subscription prepare_subscription(std::uint8_t actor,const RichonlineStockSubscriptionRequest&,
        std::uint32_t quantity,std::span<const std::uint8_t> active,const RichonlineBossCards& cards) const;
    bool commit(const Subscription&,std::span<const std::uint8_t> active,RichonlineBossCards& cards);
private:
    std::uint16_t game_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    std::shared_ptr<LuaServer> script_;
    std::vector<RichonlineStockQuote> quotes_;
    RichonlineStockIndex index_;
    std::array<std::array<RichonlineStockHolding,10>,8> holdings_{};
    float rise_limit_,fall_limit_;
    bool restricted_=false;
    std::uint64_t revision_=0;
};
}
