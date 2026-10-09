#pragma once

// 管理入口：按客户端配置启动控制服务，经命名管道接收管理请求。

#include "credentials.hpp"
#include <filesystem>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>

namespace richnet {
using ControlLog = std::function<void(const std::string&, const nlohmann::json&)>;
void run_control(const std::filesystem::path& directory, const std::wstring& pipe_name,
                 const ControlLog& log, ClientProfile profile = ClientProfile::richonline,
                 bool adopt_untagged_profile = false);
}
