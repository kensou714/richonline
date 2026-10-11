#pragma once

#include "codec.hpp"
#include <filesystem>
#include <map>
#include <span>
#include <string>

namespace richnet {
// NEW7F3C70：按初始现金判断moneyV/moneyR条件，再执行有符号低32位乘积和除100。
// 同一份Prop资源供本局所有真人和合成角色共用，不重复加载也不分叉公式。
class RichonlineInitialCash final {
public:
    explicit RichonlineInitialCash(const std::filesystem::path& root);
    std::uint32_t apply(std::uint32_t initial, std::span<const std::uint32_t> equipment) const;
private:
    std::vector<std::map<std::string, std::string, std::less<>>> props_;
};
}
