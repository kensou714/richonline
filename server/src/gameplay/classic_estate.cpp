#include "richonline_classic_property.hpp"
#include "lua_server.hpp"
#include <algorithm>

namespace richnet {
RichonlineClassicProperty::CardChange RichonlineClassicProperty::prepare_estate_effect(
    std::int16_t property,std::uint8_t actor) const {
    const auto source=snapshot(property);
    if(pending_ || actor>=ledger_->actor_count() || source.sprite_type!=12 || source.kind!=6 || !source.owner)
        throw CodecError("richonline_classic_estate_context_invalid");
    const bool improve=source.owner==actor;
    CardChange plan;plan.owner_=this;
    // 7DF010按原记录号递增生产Map+46C；后续改造不增删成员。
    // 显式排序保证人工装配资源也遵循客户端编号顺序，不使用map以外的随机顺序。
    auto order=ordinary_properties_;std::ranges::sort(order);
    for(const auto id:order) plan.before_.push_back(snapshot(id));
    if(std::ranges::find(order,property)==order.end())
        throw CodecError("richonline_classic_estate_source_not_in_list");
    plan.after_=plan.before_;
    std::optional<std::size_t> selected;
    // 自有：住宅，然后其他大型建筑；他有：住宅、商店、大型建筑。
    for(unsigned group=0;group<(improve ? 2U : 3U) && !selected;++group) {
        auto threshold=source.level;
        for(std::size_t index=0;index<plan.before_.size();++index) {
            const auto& candidate=plan.before_[index];
            const bool category=group==0 ? candidate.sprite_type==11 && candidate.kind==0 :
                !improve && group==1 ? candidate.sprite_type==11 && candidate.kind==1 : candidate.sprite_type==12;
            if(!category || candidate.owner!=actor || (improve && candidate.id==property)) continue;
            // 加盖严格小于，保留同级首项；拆除允许等于，后项覆盖同级前项。
            if(improve ? candidate.level<threshold : candidate.level>0 && candidate.level<=threshold) {
                selected=index;threshold=candidate.level;
            }
        }
    }
    LuaValue expected{{"target",-1},{"kind",-1},{"level",0}};
    if(selected) {
        auto& after=plan.after_[*selected];
        if(improve) {
            if(after.sprite_type==12 && (after.kind<2 || after.kind>6)) after.kind=3;
            after.level=static_cast<std::uint8_t>(std::min<unsigned>(5,after.level+source.level));
        } else {
            // 目标正等级不超过公司等级，因此7E4020在已验证0..5域必然拆到0。
            after.level=0;after.kind=after.sprite_type==11 ? 0 : -1;
        }
        // 商店清地的7E3E60/7E3C00先清再恢复同一owner；不转移产权或地块计时。
        expected={{"target",after.id},{"kind",after.kind},{"level",after.level}};
    }
    if(script_) {
        auto candidates=LuaValue::array();
        for(const auto& item:plan.before_) candidates.push_back({{"id",item.id},{"sprite",item.sprite_type},
            {"kind",item.kind},{"level",item.level},{"owner",item.owner ? static_cast<int>(*item.owner) : -1}});
        const auto result=script_->call("property.classic_estate",{{"source",property},{"actor",actor},
            {"level",source.level},{"improve",improve},{"candidates",std::move(candidates)}});
        if(result!=expected || !result.at("target").is_number_integer() ||
            !result.at("kind").is_number_integer() || !result.at("level").is_number_integer())
            throw CodecError("lua_classic_estate_plan_invalid");
    }
    return plan;
}
}
