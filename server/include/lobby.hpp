#pragma once

// 大厅连接与监听服务：管理握手、登录、认证后请求以及连接关闭通知。

#include "codec.hpp"

#include <atomic>
#include <functional>
#include <optional>
#include <string>

namespace richnet {

struct LobbyHandshake {
    std::uint32_t wire_type;
    std::int32_t generator;
    std::int32_t modulus;
    std::int32_t private_exponent;
};

LobbyHandshake local_lobby_handshake();

struct LobbyOptions {
    std::string host = "127.0.0.1";
    std::uint16_t port = 0;
    std::optional<LobbyHandshake> handshake;
    ClientVersion version = ClientVersion::richonline;
};

struct LobbyLogin {
    std::string username_utf8;
    // 已读取但用途尚未确认的登录字段，不作为推测的游戏配置使用。
    std::uint32_t unknown_tail_u32;
    std::uint32_t unknown_descriptor_u32 = 0;
};

struct LobbyCallbacks {
    std::function<bool(const std::string&, View)> verify_credentials;
    std::function<std::vector<Frame>(const LobbyLogin&)> login_responses;
    std::function<std::vector<Frame>(const LobbyLogin&, const Frame&)> authenticated_request;
    std::function<std::vector<Frame>()> drain_outbound = {};
    std::function<void()> disconnected = {};
    // Transport calls this only after a complete encoded frame was sent.
    std::function<void(const Frame&)> sent = {};
};

using LobbyLogSink = std::function<void(const std::string&)>;
using LobbyCallbackFactory = std::function<LobbyCallbacks()>;
enum class LobbyState { not_started, awaiting_public_key, awaiting_login, authenticated, closed };

class RichLobbySession final {
public:
    RichLobbySession(LobbyOptions options, LobbyCallbacks callbacks, LobbyLogSink log = {});
    ~RichLobbySession();
    RichLobbySession(const RichLobbySession&) = delete;
    RichLobbySession& operator=(const RichLobbySession&) = delete;
    Bytes start();
    std::vector<Bytes> feed(View chunk);
    std::vector<Bytes> poll();
    std::vector<Bytes> drain_outbound();
    void sent(View wire_frame);
    void finish();
    LobbyState state() const noexcept { return state_; }
private:
    std::vector<Frame> receive(const Frame& frame);
    void encode_responses(const std::vector<Frame>& frames, std::vector<Bytes>& output);
    void close() noexcept;
    LobbyOptions options_;
    LobbyCallbacks callbacks_;
    LobbyLogSink log_;
    LobbyState state_ = LobbyState::not_started;
    std::optional<std::int32_t> key_;
    std::optional<LobbyLogin> login_;
    Bytes pending_;
    bool disconnected_ = false;
};

class RichLobbyService final {
public:
    RichLobbyService(LobbyOptions options, LobbyCallbacks callbacks, LobbyLogSink log = {});
    RichLobbyService(LobbyOptions options, LobbyCallbackFactory factory, LobbyLogSink log = {});
    void run();
    void stop() noexcept { stopping_.store(true); }
    std::uint16_t bound_port() const noexcept { return bound_port_.load(); }
    std::uint32_t authenticated_sessions() const noexcept { return authenticated_sessions_.load(); }
private:
    LobbyOptions options_;
    LobbyCallbackFactory callback_factory_;
    LobbyLogSink log_;
    std::atomic_bool stopping_{false};
    std::atomic<std::uint16_t> bound_port_{0};
    std::atomic<std::uint32_t> authenticated_sessions_{0};
};

}
