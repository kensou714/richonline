#pragma once

// 黑名单持久层：以所有者及凭据摘要访问条目；数据库连接由实例持有。

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

struct sqlite3;

namespace richnet {
class BlacklistStoreError : public std::runtime_error {
public:
    explicit BlacklistStoreError(const std::string& code) : std::runtime_error(code) {}
};

struct BlacklistEntry {
    std::vector<std::uint8_t> target;
    bool enabled;
    bool operator==(const BlacklistEntry&) const = default;
};

class BlacklistStore {
public:
    explicit BlacklistStore(const std::filesystem::path& path);
    ~BlacklistStore();
    BlacklistStore(const BlacklistStore&) = delete;
    BlacklistStore& operator=(const BlacklistStore&) = delete;

    std::vector<BlacklistEntry> list(std::span<const std::uint8_t> owner,
                                     std::span<const std::uint8_t> digest);
    void add(std::span<const std::uint8_t> owner, std::span<const std::uint8_t> digest,
             std::span<const std::uint8_t> target);
    void add_enabled(std::span<const std::uint8_t> owner, std::span<const std::uint8_t> digest,
                     std::span<const std::uint8_t> target);
    bool remove(std::span<const std::uint8_t> owner, std::span<const std::uint8_t> digest,
                std::span<const std::uint8_t> target);
    bool set_enabled(std::span<const std::uint8_t> owner, std::span<const std::uint8_t> digest,
                     std::span<const std::uint8_t> target, bool enabled);
private:
    sqlite3* db_{};
    std::mutex mutex_;
};
}
