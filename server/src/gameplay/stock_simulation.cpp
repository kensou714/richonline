#include "richonline_stock_simulation.hpp"
#include <algorithm>
#include <cmath>
#include <set>

namespace richnet {
namespace {
constexpr float minimum_price=1.0F,maximum_price=999.99F;
void positive(float value) {
    if(!std::isfinite(value) || value<=0) throw CodecError("richonline_stock_simulation_price_invalid");
}
float sum_prices(std::span<const float> prices) {
    // 80E170每加一股就写回float；大盘不是资产加权平均或价格的整数化结果。
    float result=0;
    for(const auto price:prices) {positive(price);result+=price;}
    positive(result);return result;
}
}
std::uint32_t RichonlineStockSimulation::random_below(std::mt19937_64& random,std::uint32_t bound) {
    // 明确均匀桶，不使用CRT全局rand，也不依赖标准库distribution的实现细节。
    const auto width=static_cast<std::uint64_t>(bound);
    const auto threshold=(std::uint64_t{0}-width)%width;
    for(;;) {const auto value=random();if(value>=threshold) return static_cast<std::uint32_t>(value%width);}
}
float RichonlineStockSimulation::ordinary_price(float price,float activity,Momentum& state,
    std::mt19937_64& random) const {
    positive(price);
    // 80E770经60C4A8调用80E710（-7..+7），不是80E6B0（-3..+3）。
    // 随机函数返回double；activity乘积和走势累加分别写回float。
    const auto draw=static_cast<int>(random_below(random,1401))-700;
    const auto noise=static_cast<float>((static_cast<double>(draw)/100.0)*activity);
    if(!std::isfinite(noise)) throw CodecError("richonline_stock_simulation_activity_overflow");
    state.value=static_cast<float>(static_cast<double>(state.value)+noise);
    state.value=std::clamp(state.value,-9.0F,9.0F);
    // 原函数按符号加减计数，换向时不清零；第四次越过+3/-3才清走势。
    if(state.value>0) ++state.direction_count;
    else if(state.value<0) --state.direction_count;
    if(state.direction_count>3 || state.direction_count< -3) state={};
    const float rise_threshold=rise_limit_-0.02F,fall_threshold=fall_limit_+0.02F;
    float percent=state.value;
    if(percent<fall_threshold) percent=fall_limit_;
    else if(percent>rise_threshold) percent=rise_limit_;
    if(price>=maximum_price) {
        if(percent>0) percent/=2;
        else if(percent<0) {percent*=2;if(percent<fall_threshold) percent=fall_limit_;}
        if(state.value>0) state.value/=2;
        else if(state.value<0) state.value*=2;
    } else if(price<=minimum_price) {
        if(percent<0) percent/=2;
        else if(percent>0) {percent*=2;if(percent>rise_threshold) percent=rise_limit_;}
        if(state.value<0) state.value/=2;
        else if(state.value>0) state.value*=2;
    }
    const auto next=static_cast<float>((static_cast<double>(percent)/100.0+1.0)*price);
    if(!std::isfinite(next)) throw CodecError("richonline_stock_simulation_price_overflow");
    return std::clamp(next,minimum_price,maximum_price);
}
RichonlineStockSimulation::RichonlineStockSimulation(const RichonlineStockResources& resources,
    const RichonlineStockMap& map,std::uint64_t seed)
    :random_(seed),rise_limit_(resources.rise_limit),fall_limit_(resources.fall_limit) {
    if(!map.enabled || map.configurations.empty() || map.configurations.size()>10 ||
        !std::isfinite(rise_limit_) || !std::isfinite(fall_limit_) || rise_limit_<=0 || fall_limit_>=0)
        throw CodecError("richonline_stock_simulation_configuration_invalid");
    std::set<std::uint32_t> unique;
    for(std::size_t slot=0;slot<map.configurations.size();++slot) {
        const auto configuration=map.configurations[slot];
        if(configuration>=resources.definitions.size() || !unique.insert(configuration).second)
            throw CodecError("richonline_stock_simulation_configuration_invalid");
        const auto& resource=resources.definitions[configuration];
        if(resource.assets==0 || resource.assets>2147483647U || resource.shares==0 ||
            resource.shares>2147483647U || !std::isfinite(resource.activity) || resource.activity<0)
            throw CodecError("richonline_stock_simulation_resource_invalid");
        activities_[slot]=resource.activity;history_.push_back({configuration,{}});
    }
    // 4201需要30个历史点，而80E170只给一个初价；这里明确以初价+29次模拟预热。
    // 极端资源/种子可能全平。有限次重新生成整盘，仍全平就拒绝开局，不伪造一个拐点。
    for(unsigned attempt=0;attempt<32;++attempt) {
        momentum_={};
        for(auto& row:history_) {
            const auto& resource=resources.definitions[row.configuration];
            const float base=static_cast<float>(resource.assets)/static_cast<float>(resource.shares);
            const auto perturbation=static_cast<int>(random_below(random_,5))-3;
            row.prices[0]=static_cast<float>(static_cast<double>(perturbation)/10.0*base+base);
            positive(row.prices[0]);
        }
        for(std::size_t day=1;day<30;++day)
            for(std::size_t slot=0;slot<history_.size();++slot)
                history_[slot].prices[day]=ordinary_price(history_[slot].prices[day-1],
                    activities_[slot],momentum_[slot],random_);
        const bool flat=std::ranges::any_of(history_,[](const auto& row) {
            const auto [low,high]=std::ranges::minmax_element(row.prices);return *low==*high;
        });
        if(flat) continue;
        std::array<float,10> previous{},current{};
        for(std::size_t slot=0;slot<history_.size();++slot) {
            previous[slot]=history_[slot].prices[28];current[slot]=history_[slot].prices[29];
        }
        opening_index_={sum_prices(std::span(previous).first(history_.size())),
            sum_prices(std::span(current).first(history_.size())),0};
        return;
    }
    throw CodecError("richonline_stock_simulation_flat_history");
}
RichonlineStockSimulationWave RichonlineStockSimulation::advance(std::span<const RichonlineStockQuote> quotes,
    std::span<const std::optional<float>> forced_prices) {
    if(quotes.size()!=history_.size() || forced_prices.size()!=quotes.size())
        throw CodecError("richonline_stock_simulation_slots_invalid");
    auto next_random=random_;auto next_momentum=momentum_;
    RichonlineStockSimulationWave result;result.prices.reserve(quotes.size());
    for(std::size_t slot=0;slot<quotes.size();++slot) {
        if(quotes[slot].configuration!=static_cast<std::int32_t>(history_[slot].configuration))
            throw CodecError("richonline_stock_simulation_configuration_mismatch");
        // 普通潜在走势照常推进；强制卡只覆盖当次最终报价，不冻结其随机流或惯性。
        const auto ordinary=ordinary_price(quotes[slot].price,activities_[slot],next_momentum[slot],next_random);
        const auto price=forced_prices[slot].value_or(ordinary);
        positive(price);result.prices.push_back(price);
    }
    result.index=sum_prices(result.prices);
    // 所有分配及数值验证完成后，只有不抛异常的标量/引擎赋值。
    random_=next_random;momentum_=next_momentum;return result;
}
}
