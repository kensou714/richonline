#pragma once

#include "richonline_stock_resources.hpp"
#include <random>

namespace richnet {
struct RichonlineStockSimulationWave {
    std::vector<float> prices;
    float index;
};
// 用户确认的服务端策略：参考80E170/80E770生成历史及普通走势，每日一次，
// 大盘为现价逐股求和，额外因子为0。不是已经证实的原服线上定价算法。
// 每局使用显式种子及独立随机流，不消耗掷骰/新闻/卡片奖励的随机状态。
class RichonlineStockSimulation final {
public:
    RichonlineStockSimulation(const RichonlineStockResources&,const RichonlineStockMap&,std::uint64_t seed);
    const std::vector<RichonlineStockHistory>& history() const noexcept {return history_;}
    RichonlineStockIndex opening_index() const noexcept {return opening_index_;}
    // 上层复制本对象后调用；只有报价事务提交成功，才能以副本替换原对象。
    // 本函数自身也先准备后提交，拒绝非法行情/随机结果时不会前进内部状态。
    // 强制价格由市场核心计算，不能再加因子、夹价或减半破坏用户确认的幅度。
    RichonlineStockSimulationWave advance(std::span<const RichonlineStockQuote>,
        std::span<const std::optional<float>> forced_prices);
private:
    struct Momentum {float value=0;int direction_count=0;};
    static std::uint32_t random_below(std::mt19937_64&,std::uint32_t bound);
    float ordinary_price(float price,float activity,Momentum&,std::mt19937_64&) const;
    std::vector<RichonlineStockHistory> history_;
    std::array<float,10> activities_{};
    std::array<Momentum,10> momentum_{};
    std::mt19937_64 random_;
    float rise_limit_,fall_limit_;
    RichonlineStockIndex opening_index_{};
};
}
