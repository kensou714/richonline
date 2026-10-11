#pragma once

#include "richonline_classic_startup.hpp"
#include "richonline_classic_property.hpp"
#include "richonline_player_cards.hpp"
#include "richonline_shared_startup.hpp"
#include "richonline_opening_hand.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_classic_news.hpp"
#include "richonline_game_payment.hpp"

namespace richnet {
class RichonlineShopCatalog;
class RichonlineClassicTerminal;
class RichonlineCombatModifierResources;
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
    // 同步原子扣费，由准入层绑定账号及同一金豆支付协调器；缺席则不开放付费刷新。
    std::function<bool(std::uint8_t,std::uint32_t)> shop_refresh;
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
    // 支持单人金额、406F并列最高存款、4078整槽变卖及4072豪雨停走。
    // 4072/4078要求amount=0且无图片；4072还须提供同代GValue的motion_cards。
    // 408B..408F要求显式property和amount=0；408F无图，其余带已加载图索引。
    // 4081要求days、图片、amount=0及kidnap策略；不使用免罪卡或保险卡。
    // 407F/4087要求days、图片、amount=0及hospital策略，自动保险与收容同笔提交。
    // 指定坐牢消息须jail策略；只有4088带图，其余只带days，均允许自动1057免罪。
    // 获奖名单、手牌与实际变卖点券由共享会话计算，不能由选择策略指定。
    // 概率和图片映射不得由BOSS新闻表替代。
    std::function<RichonlineClassicMoneyNews(const RichonlineClassicTurnContext&,
        const RichonlineGameFundsSnapshot&,std::uint32_t)> select;
};
struct RichonlineClassicKidnapPolicy {
    // 原服返回位置选择尚无证据，必须由地图业务显式选择；不得猜原地或随机分布。
    // 在被绑角色天数归零的自身回合调用，只读，返回当前地图合法道路格。
    std::function<std::int16_t(const RichonlineClassicTurnContext&)> return_position;
    // 服务端排队节奏，不冒充客户端动画ACK或原服超时。客户端仍按消息队列消费。
    std::chrono::milliseconds entry_delay{6150},turn_delay{1800};
};
struct RichonlineClassicConfinementPolicy {
    std::function<bool(std::uint8_t)> secondary_insurance_absent;
    // 显式服务端排队策略，覆盖入院/入狱及可选保险动画；不是客户端确认或原服时长。
    std::chrono::milliseconds entry_delay{10000},turn_delay{3150},controlled_exit_delay{1800};
    // 普通本地角色必须回0015；到期报错，不能伪造退出确认。
    std::chrono::milliseconds exit_timeout{30000};
};
using RichonlineClassicHospitalPolicy=RichonlineClassicConfinementPolicy;
struct RichonlineClassicJailPolicy : RichonlineClassicConfinementPolicy {
    // 先查1057免罪；未免罪时才查基类的1049保险库存证明。
    std::function<bool(std::uint8_t)> secondary_pardon_absent;
};
struct RichonlineClassicAssetPolicy {
    // 同步只读，每块实际归属地产调用一次；不给未核实的估值公式设置默认值。
    std::function<std::uint64_t(const RichonlineClassicPropertyState&)> property_value;
    std::string evidence;
};
struct RichonlineClassicShopPolicy {
    // 沿用同代客户端资源；两个商品兼容字节没有已证实业务含义，须由准入层显式提供。
    std::array<std::uint8_t,2> stock_opaque;
    RichonlineGoldCharges charges;
};
struct RichonlineClassicAccountPayment {
    // 准入层已认证的房间角色和扣押金前账号余额；debit必须绑定同一账号/角色。
    std::int16_t identity;
    double account_gold;
    std::string operation_prefix;
    RichonlineGamePayment::Debit debit;
};
struct RichonlineClassicPaymentPolicy {
    RichonlineGoldCharges charges;
    std::shared_ptr<const RichonlineCombatModifierResources> equipment;
    std::vector<RichonlineClassicAccountPayment> actors;
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
    // 缺席时采用用户确认的默认规则：以买方存款尽量收购，不动用现金或卖方折让。
    std::function<std::uint32_t(const RichonlineClassicSubscriptionContext&)> subscription_quantity;
    std::optional<RichonlineClassicNewsPolicy> news;
    std::shared_ptr<const RichonlineMotionCardRules> motion_cards;
    std::optional<RichonlineClassicKidnapPolicy> kidnap;
    // 407F/4087还须地图具有已验证的医院入口/出口；不复用绑架返回位置策略。
    std::optional<RichonlineClassicHospitalPolicy> hospital;
    std::optional<RichonlineClassicJailPolicy> jail;
    std::optional<RichonlineClassicAssetPolicy> asset_settlement;
    std::optional<RichonlineClassicShopPolicy> shop;
    std::optional<RichonlineClassicPaymentPolicy> payment;
    // 大型空地的UI13流程；group0使用world.cards，group1必须由库存准入提供无可用证明。
    std::shared_ptr<const RichonlineClassicConstructionResources> buildings;
    std::function<bool(std::uint8_t,std::int16_t)> secondary_building_licence_absent;
};
// 返回一份整局业务，必须经宿主的make_richonline_shared_startups装配，不能直接
// 将action绑定到每条连接；0011/0028由共享层全员汇合后才提交位置和落点/银行。
// 生产接入仍须提供特殊格、租金、结算等完整业务，不能仅开放模式门。
RichonlineSharedCallbacks make_richonline_classic_session(const RichonlineClassicStartup&,
    RichonlineClassicSessionRules);
}
