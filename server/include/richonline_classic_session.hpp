#pragma once

#include "richonline_classic_startup.hpp"
#include "richonline_classic_property.hpp"
#include "richonline_player_cards.hpp"
#include "richonline_shared_startup.hpp"
#include "richonline_opening_hand.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_classic_news.hpp"

namespace richnet {
class RichonlineShopCatalog;
class RichonlineClassicTerminal;
// 所有连接共用这些对象。业务回调只能在shared_startups持有的对局锁内访问。
struct RichonlineClassicWorld {
    std::shared_ptr<RichonlineGameLedger> ledger;
    std::shared_ptr<RichonlineClassicProperty> property;
    std::vector<std::shared_ptr<RichonlinePlayerCards>> cards;
    std::shared_ptr<RichonlineStockMarket> stocks;
};
struct RichonlineClassicTurnContext {
    std::uint16_t game_id,calendar;
    std::uint64_t sequence,completed_rounds;
    RichonlineLandingContext landing;
    // 完整位置和各人的状态来自同一局，不能用当前连接的local_slot替代行动槽。
    std::span<const RichonlineBoardParticipant> participants;
    std::span<const RichonlineActorStatus> statuses;
    // 破产保留槽位及网络成员，只有活动资格清零；业务选择必须排除非活动槽。
    std::span<const std::uint8_t> active;
};
struct RichonlineClassicServices {
    // 传送格由会话独立续接；其余特殊格和复杂地产先由业务接管。
    // 空值才进入普通路/卡片格/地产选择，且表示业务没有提交副作用。
    // 同格phase6统一由会话在complete之后执行，业务不得提前提交或重复提交同格转移。
    std::function<std::optional<RichonlineLandingResult>(const RichonlineClassicTurnContext&)> landing;
    // 购地、升级、取消、余额不足后均进入这里；不能把4020/4021等同于回合结束。
    std::function<RichonlineLandingResult(const RichonlineClassicTurnContext&)> property_effects;
    // 股票成交独立于当前行动者及落点选择。待决事件提交时须重新读取world.ledger，
    // 不把打开选择框时的余额当作不可变资金；事件固定金额/资格仍由业务自己复核。
    std::function<RichonlineLandingResult(const RichonlineClassicTurnContext&,View)> event;
    std::function<std::optional<RichonlineLandingResult>(const RichonlineClassicTurnContext&)> poll;
    std::function<void(std::uint8_t)> disconnected;
};
struct RichonlineClassicStockPolicy {
    std::shared_ptr<const RichonlineStockResources> resources;
    std::vector<RichonlineStockHistory> history;
    float previous_index,current_index,factor;
};
struct RichonlineClassicSubscriptionContext {
    std::uint8_t buyer,seller;
    std::uint16_t stock_slot;
    RichonlineStockQuote quote;
    RichonlineStockHolding buyer_holding,seller_holding;
    RichonlineGameFundsSnapshot buyer_funds,seller_funds;
};
struct RichonlineClassicNewsPolicy {
    // 同步只读选择：自行按真实地图规则选事件及金额，不改账本/手牌/状态、不发包。
    // 支持单人金额、406F并列最高存款及4078整槽变卖；4078要求amount=0且无图片。
    // 获奖名单、手牌与实际变卖点券由共享会话计算，不能由选择策略指定。
    // 概率和图片映射不得由BOSS新闻表替代。
    std::function<RichonlineClassicMoneyNews(const RichonlineClassicTurnContext&,
        const RichonlineGameFundsSnapshot&,std::uint32_t)> select;
};
struct RichonlineClassicSessionRules {
    // 起始槽、骰数、起手牌均为显式策略；不借用BOSS先手或BOSS奖池。
    std::uint8_t first_actor,opaque_turn7;
    std::vector<std::uint8_t> maximum_dice;
    std::array<std::int8_t,2> inactive_ui_dice;
    RichonlineRouteWirePolicy route_wire;
    RichonlineRouteChooser random;
    std::function<std::chrono::steady_clock::time_point()> now;
    std::chrono::milliseconds decision_timeout;
    std::shared_ptr<const RichonlineChanceResources> card_resources;
    std::shared_ptr<const RichonlineShopCatalog> resale;
    std::vector<std::vector<RichonlineMapOpeningCard>> opening_hands;
    std::vector<std::int16_t> random_reward_cards;
    std::shared_ptr<LuaServer> script;
    std::function<RichonlineClassicServices(const RichonlineClassicWorld&)> services;
    GameLogSink log;
    // 显式提供原协议未命名字节；缺席时维持银行未开放，不推测padding。
    std::optional<RichonlineGameBankWirePolicy> bank_wire;
    // NEW7F85C0先查局内手牌，再查角色第二套卡槽。金额达到自动卡门槛且手牌
    // 未抵扣时，必须由库存业务同步只读地证明第二套没有可用1050/1056；缺席表示未知。
    std::function<bool(std::uint8_t)> secondary_rent_cards_absent;
    // 由受信任准入层绑定全部账号、实际押金及经典奖励策略。缺席时不开放最终结算。
    std::function<std::unique_ptr<RichonlineClassicTerminal>(const RichonlineClassicWorld&)> settlement;
    // 准入层明确提供按地图槽排列的真实初始行情；缺席时不开放股票，不生成假历史。
    std::optional<RichonlineClassicStockPolicy> stocks;
    // 0096没有数量字段。策略只读本次快照并返回数量，不得修改市场/账本或发包。
    // 缺席时仅支持已无持仓的40E6零数量确认；有持仓则恢复操作，不猜全量/最大数量。
    std::function<std::uint32_t(const RichonlineClassicSubscriptionContext&)> subscription_quantity;
    std::optional<RichonlineClassicNewsPolicy> news;
};
// 返回一份整局业务，必须经宿主的make_richonline_shared_startups装配，不能直接
// 将action绑定到每条连接；0011/0028由共享层全员汇合后才提交位置和落点/银行。
// 生产接入仍须提供特殊格、租金、结算等完整业务，不能仅开放模式门。
RichonlineSharedCallbacks make_richonline_classic_session(const RichonlineClassicStartup&,
    RichonlineClassicSessionRules);
}
