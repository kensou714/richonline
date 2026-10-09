#pragma once

// Windows 管理管道：封装连接、文本读写和客户端关闭等待，句柄由实例管理。
#include "windows_handle.hpp"
#include <chrono>
#include <cstdint>
#include <span>
#include <string>

namespace richnet {
class ControlPipe final {
public:
    explicit ControlPipe(const std::wstring& name);
    ~ControlPipe();
    ControlPipe(const ControlPipe&) = delete;
    ControlPipe& operator=(const ControlPipe&) = delete;
    void accept();
    std::string read();
    void write(const std::string& text);
    void disconnect();
    void await_client_close();
private:
    WindowsHandle pipe_;
    std::chrono::steady_clock::time_point deadline_;
    void transfer(std::span<std::uint8_t> bytes, bool writing);
};
}
