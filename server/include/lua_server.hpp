#pragma once

// 正式服 Lua 宿主。每个会话拥有独立 VM；原生接口仅在当前事件调用期间有效。
// 参数使用 JSON 值桥接为 Lua 表，二进制报文使用可含零字节的字符串。
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <nlohmann/json.hpp>

namespace richnet {
using LuaValue = nlohmann::json;
using LuaNative = std::function<LuaValue(const LuaValue&)>;
using LuaBindings = std::map<std::string, LuaNative, std::less<>>;

class LuaServer final {
public:
    // 发布不可变脚本快照。完整加载失败时不替换旧版本，已有会话继续使用旧快照。
    static void configure(const std::filesystem::path& root);
    static std::shared_ptr<LuaServer> create();
    static LuaValue status();
    ~LuaServer();
    LuaServer(const LuaServer&) = delete;
    LuaServer& operator=(const LuaServer&) = delete;
    LuaValue call(const std::string& event, const LuaValue& request, const LuaBindings& bindings = {});
private:
    struct Impl;
    explicit LuaServer(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};
}
