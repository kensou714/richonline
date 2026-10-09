#pragma once

// Lua 策略入口：接收脚本路径及整数抽取序列，返回策略产生的字符串结果。

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace richnet {
std::vector<std::string> run_policy(const std::string& path, std::span<const std::int64_t> draws);
}
