#pragma once

// 辅助服务：提供频道入口 HTTP 与黑名单端口；连接事件通过日志回调交给宿主。

#include "codec.hpp"
#include "channel_catalog.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace richnet {

enum class AuxiliaryKind { http, black, intro, inquiry };

struct AuxiliaryOptions {
    std::string bind_host = "127.0.0.1";
    std::string advertised_host = "127.0.0.1";
    std::uint16_t http_port = 18680;
    std::uint16_t black_port = 18604;
    std::uint16_t lobby_port = 18600;
    std::uint32_t capacity = 100;
    std::uint32_t channel_id = 0;
    std::function<std::uint32_t()> current_players;
    std::function<Bytes(View)> black_response;
    // NEW area config has a separate intro endpoint. Disabled for old profiles.
    std::optional<std::uint16_t> intro_port;
    std::function<std::optional<Bytes>(View)> intro_response;
    std::optional<std::uint16_t> inquiry_port;
    std::function<std::optional<Bytes>(View)> inquiry_response;
    std::optional<std::uint32_t> lobby_type;
    ChannelCatalog channels;
    std::function<std::uint32_t(std::uint32_t)> channel_players;
};

struct AuxiliaryEvent {
    std::string_view event;
    AuxiliaryKind service;
    std::uint64_t connection_id = 0;
    std::string_view reason;
    std::optional<std::uint32_t> wire_type;
    std::size_t request_bytes = 0;
    std::size_t response_bytes = 0;
    std::uint16_t port = 0;
};

using AuxiliaryLogSink = std::function<void(const AuxiliaryEvent&)>;

// 调用方持有运行线程，在 stop() 后负责 join；每个实例只允许调用一次 run()。
class AuxiliaryService final {
public:
    explicit AuxiliaryService(AuxiliaryOptions options, AuxiliaryLogSink log = {});
    void run();
    void stop() noexcept { stopping_.store(true); }
    std::uint16_t bound_http_port() const noexcept { return http_port_.load(); }
    std::uint16_t bound_black_port() const noexcept { return black_port_.load(); }
    std::uint16_t bound_intro_port() const noexcept { return intro_port_.load(); }
    std::uint16_t bound_inquiry_port() const noexcept { return inquiry_port_.load(); }
private:
    AuxiliaryOptions options_;
    AuxiliaryLogSink log_;
    std::atomic_bool stopping_{false};
    std::atomic<std::uint16_t> http_port_{0};
    std::atomic<std::uint16_t> black_port_{0};
    std::atomic<std::uint16_t> intro_port_{0};
    std::atomic<std::uint16_t> inquiry_port_{0};
};

}
