#pragma once
#include "richonline_boss_turns.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_chance.hpp"
#include "richonline_raw_authority.hpp"
#include "richonline_classic_property.hpp"

namespace richnet {
class RichonlineShopCatalog;
struct RichonlineMotionCardRules;
// NEW 64F2A0 -> 7D9C70在每次开局将G+C80设为5000，与地图起始现金无关。
inline constexpr std::uint32_t richonline_classic_initial_news_fines=5000;
struct RichonlineClassicMoneyNews {
    std::uint16_t opcode;
    std::uint32_t amount;
    // 只有UI30分支有图索引；UI4分支没有这个字段，不能补一个占位WORD。
    std::optional<std::int16_t> picture;
    // 408B..408F的地产表索引；不是道路格号、角色槽或金额。
    std::optional<std::int16_t> property{};
    // 处罚状态独立于金额；4081直接写入signed BYTE天数，不从固定文案推导。
    std::optional<std::uint8_t> days{};
};
struct RichonlineClassicNewsPlan {
    RichonlineGameFundsUpdate funds;
    std::uint32_t fines_before,fines_after;
    bool bankrupt;
    std::vector<Bytes> messages;
};
struct RichonlineClassicSavingsNewsPlan {
    // 包含未获奖者：提交时也核对其存款版本，防止第一名资格在准备后改变。
    std::vector<RichonlineGameFundsUpdate> funds;
    std::vector<std::uint8_t> recipients;
    std::vector<Bytes> messages;
};
struct RichonlineClassicCardSaleNewsPlan {
    RichonlineGameFundsUpdate funds;
    RichonlineChanceInventory inventory_before,inventory_after;
    std::uint32_t tickets_received;
    std::vector<Bytes> messages;
};
struct RichonlineClassicRainActor {
    bool active;
    RichonlineRawActorState raw;
    RichonlineActorStatus status;
    bool operator==(const RichonlineClassicRainActor&) const = default;
};
struct RichonlineClassicRainNewsPlan {
    std::vector<RichonlineClassicRainActor> before,after;
    std::vector<Bytes> messages;
};
struct RichonlineClassicKidnapNewsPlan {
    RichonlineRawActorState raw_before;
    RichonlineActorStatus before,after;
    std::uint8_t days;
    std::vector<Bytes> messages;
};
struct RichonlineClassicConfinementNewsPlan {
    RichonlineRawActorState raw_before;
    RichonlineActorStatus before,after;
    RichonlineGameFundsUpdate funds;
    RichonlineChanceInventory inventory_before,inventory_after;
    std::uint8_t days;
    std::int8_t insurance_slot;
    std::uint32_t compensation;
    std::vector<Bytes> messages;
    std::int8_t pardon_slot=-1;
};
using RichonlineClassicHospitalNewsPlan=RichonlineClassicConfinementNewsPlan;
using RichonlineClassicJailNewsPlan=RichonlineClassicConfinementNewsPlan;
bool richonline_classic_jail_news(std::uint16_t opcode) noexcept;
RichonlineClassicJailNewsPlan prepare_richonline_classic_jail_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,const RichonlineRawActorState&,
    const RichonlineGameFundsSnapshot&,const RichonlineChanceInventory&,const RichonlineChanceResources&,
    std::string_view map,bool secondary_pardon_absent,bool secondary_insurance_absent,
    const std::shared_ptr<LuaServer>&);
// 407F/4087的动画9自动处理保险1049；不另发扣卡/加现金包以免客户端执行两次。
// 手牌没有保险时，secondary_insurance_absent必须来自真实第二套卡槽的只读证明。
RichonlineClassicHospitalNewsPlan prepare_richonline_classic_hospital_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,const RichonlineRawActorState&,
    const RichonlineGameFundsSnapshot&,const RichonlineChanceInventory&,const RichonlineChanceResources&,
    std::string_view map,bool secondary_insurance_absent,const std::shared_ptr<LuaServer>&);
RichonlineClassicKidnapNewsPlan prepare_richonline_classic_kidnap_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,
    const RichonlineRawActorState&,const std::shared_ptr<LuaServer>&);
Bytes prepare_richonline_classic_kidnap_return(std::uint16_t game,std::int16_t position,
    const std::shared_ptr<LuaServer>&);
// 返回已验证报文；产权变更仍由会话在所有准备完成后提交。
std::vector<Bytes> prepare_richonline_classic_disaster_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,
    const RichonlineClassicProperty::Disaster&,const std::shared_ptr<LuaServer>&);
// 4072只筛活动及四个原始收容状态；直接覆盖stay，不使用攻击卡免疫或额外加一。
RichonlineClassicRainNewsPlan prepare_richonline_classic_rain_news(std::uint16_t game,
    const RichonlineLandingContext&,std::span<const RichonlineClassicRainActor>,
    const RichonlineMotionCardRules&,const std::shared_ptr<LuaServer>&);
// 4078整槽变卖：每个非空槽只计一次priceG，清掉整叠；不乘数量、不打半价。
RichonlineClassicCardSaleNewsPlan prepare_richonline_classic_card_sale_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineGameFundsSnapshot&,
    const RichonlineChanceInventory&,const RichonlineShopCatalog&,const std::shared_ptr<LuaServer>&);
// 406F客户端自行按全部活动角色的最高存款选人，每位并列者获得完整金额。
// 不把现金、股票或预备金计入排名；全员零存款时全部活动角色获奖。
RichonlineClassicSavingsNewsPlan prepare_richonline_classic_savings_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,
    std::span<const RichonlineGameFundsSnapshot>,std::span<const std::uint8_t> active,
    const std::shared_ptr<LuaServer>& script);
// 对应406D/406E收入及已核实的单人罚款消息。只准备，不选概率、不写账本。
// 图片索引按NEW UI30的718DE0初始化表校验，不能把数组容量当成已加载图片。
RichonlineClassicNewsPlan prepare_richonline_classic_money_news(std::uint16_t game,
    const RichonlineLandingContext&,const RichonlineClassicMoneyNews&,
    const RichonlineGameFundsSnapshot&,std::uint32_t fines,
    const std::shared_ptr<LuaServer>& script);
}
