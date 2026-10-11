#pragma once

#include "richonline_actor_status.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_property_resources.hpp"
#include "richonline_route.hpp"
#include "richonline_construction_resources.hpp"
#include "richonline_player_cards.hpp"
#include <chrono>
#include <map>
#include <memory>

namespace richnet {
class LuaServer;
enum class RichonlineClassicPropertyChoice { purchase, upgrade };
enum class RichonlineClassicPropertyOutcome { accepted, declined, timed_out, insufficient_funds, licence_missing };
enum class RichonlineClassicPropertyContinuation { property_effects, building_choice };
struct RichonlineClassicBuildingPolicy {
    std::shared_ptr<const RichonlineClassicConstructionResources> resources;
    // 与会话其余玩法共用的group0手牌。不能复制为建筑模块的私有库存。
    std::vector<std::shared_ptr<RichonlinePlayerCards>> cards;
    // group1尚未接入事务；准入层须同步只读地证明指定许可证不可从group1使用。
    // 缺少证明表示未知，不能把局内8槽没有许可证当作全部背包没有许可证。
    std::function<bool(std::uint8_t,std::int16_t)> secondary_licence_absent;
};
struct RichonlineClassicPropertyState {
    std::int16_t id;
    std::int8_t sprite_type,kind;
    std::uint8_t level;
    std::optional<std::uint8_t> owner;
    std::uint32_t price;
    // D+4查封剩余天数，属于地块本身，不随换地/换屋转移。
    std::uint8_t sealed_days=0;
    bool operator==(const RichonlineClassicPropertyState&) const = default;
};
struct RichonlineClassicPropertyEntry {
    std::uint16_t game_id,calendar;
    std::uint64_t turn_sequence;
    std::uint8_t actor;
    std::int16_t position,property;
    // 来自当前行动者的真实P+152，不用未提供的装备值推导半价。
    std::int32_t land_equipment;
    RichonlineActorStatus status;
    bool sealed;
    bool operator==(const RichonlineClassicPropertyEntry&) const = default;
};
struct RichonlineClassicPropertyResult {
    Bytes message;
    RichonlineClassicPropertyEntry entry;
    RichonlineClassicPropertyState before,after;
    RichonlineClassicPropertyOutcome outcome;
    std::uint32_t charged;
    // 4021可转UI13；终态4020/4021/4025才续行附加效果，均不等于回合结束。
    RichonlineClassicPropertyContinuation continuation=RichonlineClassicPropertyContinuation::property_effects;
};
// mode0真人2..4的单局地产所有权。由共享对局锁串行调用，禁止每个连接复制一份。
// 本类只接受上层落点分流已授权的购地/普通升级选择：上层先处理碰撞、类型2/6
// 的前置效果及控制状态，之后才begin。它不替代完整落点分派，也不负责发送4013。
class RichonlineClassicProperty final {
public:
    using Clock=std::chrono::steady_clock;
    using Now=std::function<Clock::time_point()>;
    RichonlineClassicProperty(std::uint16_t game_id,RichonlineRoadTopology topology,
        const RichonlinePropertyResources& resources,std::shared_ptr<RichonlineGameLedger> ledger,
        Now now,std::chrono::milliseconds timeout,std::shared_ptr<LuaServer> script={},
        std::optional<RichonlineClassicBuildingPolicy> buildings={});
    RichonlineClassicProperty(const RichonlineClassicProperty&)=delete;
    RichonlineClassicProperty& operator=(const RichonlineClassicProperty&)=delete;
    RichonlineClassicPropertyState snapshot(std::int16_t property) const;
    std::uint16_t game_id() const noexcept {return game_id_;}
    bool uses_ledger(const RichonlineGameLedger& ledger) const noexcept {return ledger_.get()==&ledger;}
    class CardChange final {
    public:
        std::span<const RichonlineClassicPropertyState> before() const noexcept {return before_;}
        std::span<const RichonlineClassicPropertyState> after() const noexcept {return after_;}
    private:
        CardChange()=default;
        const RichonlineClassicProperty* owner_=nullptr;
        std::vector<RichonlineClassicPropertyState> before_,after_;
        friend class RichonlineClassicProperty;
    };
    // 购地/交换/拆除分别检查产权、地类和保护建筑；拆除还须有建筑。
    // 购地只换产权；换地只换两端产权；换屋只换种类/等级，不换价格和街区。
    CardChange prepare_card_purchase(std::int16_t property,std::uint8_t actor) const;
    CardChange prepare_card_swap(std::int16_t source,std::int16_t target,bool buildings) const;
    CardChange prepare_card_destruction(std::int16_t property,std::uint8_t levels) const;
    // 同街区普通地产表成员重设5天，不限所有权/等级；初始kind8/9/10不在此表。
    CardChange prepare_card_seal(std::int16_t property) const;
    bool matches(const CardChange&) const noexcept;
    bool commit_card_change(const CardChange&) noexcept;
    // 只在4010实际推进日期时调用；首次轮首和同日其余玩家不递减。
    // completed_rounds从1开始连续递增，重复同轮不再扣天数。
    void advance_seals(std::uint64_t completed_rounds);
    // 只将当前实际归属的地产交给只读估值策略；禁止未决交易期间冻结排名。
    // 策略须另有估值依据，不能把购地花费、租金或升级费用自动当作资产价格。
    std::vector<std::uint64_t> asset_values(
        const std::function<std::uint64_t(const RichonlineClassicPropertyState&)>& valuation) const;
    // 只用于本对象持有的普通住宅/同类地产；落点查封在收租入口拦截，加倍卡尚无写入口。
    // 按NEW的32位乘法、逐块有符号除法和累加顺序返回报价，负值不能当无租金。
    std::int32_t rent_quote(std::int16_t property,std::uint32_t monetary_scale) const;
    class Retirement final {
    public:
        std::uint8_t actor() const noexcept {return actor_;}
    private:
        Retirement()=default;
        const RichonlineClassicProperty* owner_=nullptr;
        std::uint8_t actor_=0;
        std::map<std::int16_t,RichonlineClassicPropertyState> before_;
        friend class RichonlineClassicProperty;
    };
    Retirement prepare_retirement(std::uint8_t actor) const;
    bool matches(const Retirement&) const noexcept;
    // 全图产权快照须一致且不能有未决购地。提交只清owner，保留种类/等级/价格。
    bool commit_retirement(const Retirement&) noexcept;
    class Disaster final {
    public:
        const RichonlineClassicPropertyState& before() const noexcept { return before_; }
        const RichonlineClassicPropertyState& after() const noexcept { return after_; }
        std::uint8_t levels() const noexcept { return levels_; }
    private:
        Disaster()=default;
        const RichonlineClassicProperty* owner_=nullptr;
        RichonlineClassicPropertyState before_{},after_{};
        std::uint8_t levels_=0;
        friend class RichonlineClassicProperty;
    };
    // 新闻灾难允许落在他人/无主地产；8/9/10或零级仍生成合法无效果新闻。
    // 计划不可由业务改写，提交前核对本对象、目标快照及未决地产选择。
    Disaster prepare_disaster(std::int16_t property,std::uint8_t levels) const;
    bool commit_disaster(const Disaster&) noexcept;
    // 返回应等待的C2S opcode；不支持的选择抛错，不伪造成功或跳过落点。
    std::uint16_t begin(RichonlineClassicPropertyChoice,const RichonlineClassicPropertyEntry&);
    // sender_actor由已认证连接提供；current必须从当前权威回合读取，不能回传旧entry冒充。
    RichonlineClassicPropertyResult handle(std::uint8_t sender_actor,View request,
        const RichonlineClassicPropertyEntry& current);
    std::optional<RichonlineClassicPropertyResult> poll(const RichonlineClassicPropertyEntry& current);
    bool active() const noexcept { return pending_.has_value(); }
private:
    struct Pending {
        RichonlineClassicPropertyChoice choice;
        RichonlineClassicPropertyEntry entry;
        RichonlineClassicPropertyState property;
        std::uint32_t cost;
        Clock::time_point deadline;
        bool building_choice=false;
    };
    std::uint16_t game_id_;
    RichonlineRoadTopology topology_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    Now now_;
    std::chrono::milliseconds timeout_;
    std::shared_ptr<LuaServer> script_;
    std::optional<RichonlineClassicBuildingPolicy> buildings_;
    std::map<std::int16_t,RichonlineClassicPropertyState> properties_;
    std::map<std::int16_t,std::int16_t> districts_;
    // 7DF010载入时构造Map+46C表；后续建筑变化不重算成员资格。
    std::vector<std::int16_t> seal_properties_;
    std::optional<Pending> pending_;
    std::uint64_t last_seal_round_=0;
    void validate_entry(const RichonlineClassicPropertyEntry&) const;
    void validate_pending(const RichonlineClassicPropertyEntry&) const;
    RichonlineClassicPropertyResult finish(bool requested,bool timed_out);
    RichonlineClassicPropertyResult finish_building(std::int8_t kind,bool timed_out);
    void validate_building_inventory(std::uint8_t actor) const;
};
}
