#pragma once

#include "richonline_classic_property.hpp"

namespace richnet {
struct RichonlineClassicResearchRequest {
    std::uint16_t calendar;
    std::int8_t choice;
    std::uint8_t opaque_tail;
};
RichonlineClassicResearchRequest decode_richonline_classic_research_request(View request);
Bytes richonline_classic_research_response(std::uint16_t game_id,std::int8_t choice);
struct RichonlineClassicResearchJob {
    std::int16_t property;
    std::uint8_t actor,choice,remaining_scans;
    bool operator==(const RichonlineClassicResearchJob&) const = default;
};
struct RichonlineClassicResearchResult {
    Bytes message;
    RichonlineClassicPropertyEntry entry;
    std::int8_t choice;
    std::optional<std::size_t> registered_slot;
    bool timed_out;
};
struct RichonlineClassicResearchScan {
    std::size_t completed=0,cancelled=0,discarded_full=0;
    bool replayed=false;
};
// 经典kind2的六字节登记表，不复用BOSS kind11的十二字节研发记录。
// 全部方法在同一共享对局锁内调用。奖励由4010/日历恢复触发的本地6061显示，
// 本对象只同步权威库存，不能额外再发送一份网络加卡消息。
class RichonlineClassicResearch final {
public:
    RichonlineClassicResearch(std::uint16_t game_id,const RichonlineRoadTopology& topology,
        const RichonlinePropertyResources& map,std::shared_ptr<RichonlineClassicProperty> property,
        std::vector<std::shared_ptr<RichonlinePlayerCards>> cards,
        std::shared_ptr<const RichonlineChanceResources> resources,
        RichonlineClassicProperty::Now now,std::chrono::milliseconds timeout,
        std::shared_ptr<LuaServer> script={});
    bool registered(std::int16_t property,std::uint8_t actor) const noexcept;
    void begin(const RichonlineClassicPropertyEntry&);
    RichonlineClassicResearchResult handle(std::uint8_t sender,View request,
        const RichonlineClassicPropertyEntry& current);
    std::optional<RichonlineClassicResearchResult> poll(const RichonlineClassicPropertyEntry& current);
    bool active() const noexcept {return pending_.has_value();}
    // scan_id来自权威调度检查点，单调递增。日历/开奖尚未续行至7E4C50前不能调用。
    // 重播同一id/actor不再递减；同一回合的另一次真实扫描须使用新的id。
    RichonlineClassicResearchScan advance(std::uint8_t actor,std::uint64_t scan_id);
    void retire(std::uint8_t actor) noexcept;
    const std::vector<std::optional<RichonlineClassicResearchJob>>& jobs() const noexcept {return jobs_;}
private:
    struct Pending {
        RichonlineClassicPropertyEntry entry;
        RichonlineClassicPropertyState property;
        RichonlineClassicProperty::Clock::time_point deadline;
    };
    std::uint16_t game_id_;
    RichonlineRoadTopology topology_;
    std::shared_ptr<RichonlineClassicProperty> property_;
    std::vector<std::shared_ptr<RichonlinePlayerCards>> cards_;
    std::shared_ptr<const RichonlineChanceResources> resources_;
    RichonlineClassicProperty::Now now_;
    std::chrono::milliseconds timeout_;
    std::shared_ptr<LuaServer> script_;
    std::vector<std::optional<RichonlineClassicResearchJob>> jobs_;
    std::optional<Pending> pending_;
    std::uint64_t last_scan_=0;
    std::uint8_t last_actor_=0;
    void validate_entry(const RichonlineClassicPropertyEntry&) const;
    void validate_pending(const RichonlineClassicPropertyEntry&) const;
    RichonlineClassicResearchResult finish(std::int8_t choice,bool timed_out);
};
}
