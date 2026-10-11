#pragma once

#include "richonline_actor_status.hpp"
#include "richonline_game_ledger.hpp"
#include "richonline_property_resources.hpp"
#include "richonline_route.hpp"
#include <chrono>
#include <map>
#include <memory>

namespace richnet {
class LuaServer;
enum class RichonlineClassicPropertyChoice { purchase, upgrade };
enum class RichonlineClassicPropertyOutcome { accepted, declined, timed_out, insufficient_funds };
enum class RichonlineClassicPropertyContinuation { property_effects };
struct RichonlineClassicPropertyState {
    std::int16_t id;
    std::int8_t sprite_type,kind;
    std::uint8_t level;
    std::optional<std::uint8_t> owner;
    std::uint32_t price;
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
    // 4020/4021均先续行附加效果；这里完成选择不代表已经完成落点或回合。
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
        Now now,std::chrono::milliseconds timeout,std::shared_ptr<LuaServer> script={});
    RichonlineClassicProperty(const RichonlineClassicProperty&)=delete;
    RichonlineClassicProperty& operator=(const RichonlineClassicProperty&)=delete;
    RichonlineClassicPropertyState snapshot(std::int16_t property) const;
    // 只将当前实际归属的地产交给只读估值策略；禁止未决交易期间冻结排名。
    // 策略须另有估值依据，不能把购地花费、租金或升级费用自动当作资产价格。
    std::vector<std::uint64_t> asset_values(
        const std::function<std::uint64_t(const RichonlineClassicPropertyState&)>& valuation) const;
    // 只用于本对象持有的普通住宅/同类地产；当前对象尚无封闭、加倍卡写入口。
    // 按NEW的32位乘法、逐块有符号除法和累加顺序返回报价，负值不能当无租金。
    std::int32_t rent_quote(std::int16_t property,std::uint32_t monetary_scale) const;
    class Retirement final {
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
    };
    std::uint16_t game_id_;
    RichonlineRoadTopology topology_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    Now now_;
    std::chrono::milliseconds timeout_;
    std::shared_ptr<LuaServer> script_;
    std::map<std::int16_t,RichonlineClassicPropertyState> properties_;
    std::map<std::int16_t,std::int16_t> districts_;
    std::optional<Pending> pending_;
    void validate_entry(const RichonlineClassicPropertyEntry&) const;
    void validate_pending(const RichonlineClassicPropertyEntry&) const;
    RichonlineClassicPropertyResult finish(bool requested,bool timed_out);
};
}
