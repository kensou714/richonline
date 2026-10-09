#pragma once

// Windows 句柄所有权：自动关闭有效句柄，仅支持移动构造，错误信息保留 Win32 错误码。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdexcept>
#include <string>
#include <utility>

namespace richnet {
inline std::runtime_error windows_error(const char* operation) {
    return std::runtime_error(std::string(operation) + ":win32=" + std::to_string(GetLastError()));
}
class WindowsHandle final {
public:
    explicit WindowsHandle(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
    ~WindowsHandle() { if (valid()) CloseHandle(handle_); }
    WindowsHandle(const WindowsHandle&) = delete;
    WindowsHandle& operator=(const WindowsHandle&) = delete;
    WindowsHandle(WindowsHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr; }
    // 借用句柄；调用方不得关闭它或把所有权交给其他对象。
    HANDLE get() const { return handle_; }
private:
    HANDLE handle_;
};
}
