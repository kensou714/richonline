#include "service.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <array>
#include <map>
#include <memory>
#include <utility>

namespace richnet {
namespace {
#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket invalid_socket = INVALID_SOCKET;
void close_socket(Socket socket) { if (socket != invalid_socket) closesocket(socket); }
struct NetworkRuntime {
    NetworkRuntime() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2,2), &data) != 0) throw CodecError("game_winsock_start_failed");
    }
    ~NetworkRuntime() { WSACleanup(); }
};
#else
using Socket = int;
constexpr Socket invalid_socket = -1;
void close_socket(Socket socket) { if (socket != invalid_socket) ::close(socket); }
struct NetworkRuntime {};
#endif
struct OwnedSocket {
    Socket value;
    explicit OwnedSocket(Socket socket) : value(socket) {}
    ~OwnedSocket() { close_socket(value); }
    OwnedSocket(const OwnedSocket&) = delete;
    OwnedSocket& operator=(const OwnedSocket&) = delete;
    OwnedSocket(OwnedSocket&& other) noexcept : value(std::exchange(other.value,invalid_socket)) {}
};
struct BoundPortReset {
    std::atomic<std::uint16_t>& port;
    ~BoundPortReset() { port.store(0); }
};
void send_bytes(Socket socket, View bytes) {
    while (!bytes.empty()) {
        const auto sent = ::send(socket,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);
        if (sent <= 0) throw CodecError("game_send_failed");
        bytes = bytes.subspan(static_cast<std::size_t>(sent));
    }
}
void configure_peer(Socket socket) {
#ifdef _WIN32
    const DWORD timeout = 1000;
#else
    const timeval timeout{1,0};
#endif
    if (setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) != 0)
        throw CodecError("game_send_timeout_setup_failed");
}
struct Peer {
    OwnedSocket socket;
    GameSession session;
    std::chrono::steady_clock::time_point admission_deadline;
    GameLogSink log;
    Peer(OwnedSocket&& accepted, ClientVersion version, GameCallbacks callbacks,
         std::chrono::steady_clock::time_point deadline, GameLogSink sink)
        : socket(std::move(accepted)), session(version,std::move(callbacks),sink),
          admission_deadline(deadline), log(std::move(sink)) {}
    void finish(std::string reason) {
        try { session.finish(); }
        catch (const std::exception& error) { reason += " cleanup_reason=" + std::string(error.what()); }
        catch (...) { reason += " cleanup_reason=unknown_exception"; }
        if (log) log("game_connection_closed reason=" + reason);
    }
};
}

GameService::GameService(ServiceOptions options, GameCallbackFactory factory, LogSink log)
    : options_(std::move(options)), factory_(std::move(factory)), log_(std::move(log)) {
    if (!factory_) throw CodecError("game_callback_factory_required");
    if (options_.admission_timeout.count() <= 0) throw CodecError("game_admission_timeout_invalid");
}
GameService::~GameService() { stop(); }
void GameService::stop() noexcept { stopping_.store(true); }

void GameService::run() {
    const GameSession preflight(options_.version,{});
    const NetworkRuntime network;
    const BoundPortReset reset{bound_port_};
    const OwnedSocket listener(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    if (listener.value == invalid_socket) throw CodecError("game_socket_create_failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(options_.port);
    if (inet_pton(AF_INET,options_.host.c_str(),&address.sin_addr) != 1) throw CodecError("game_invalid_bind_address");
    if (::bind(listener.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address)) != 0) throw CodecError("game_bind_failed");
    if (::listen(listener.value,32) != 0) throw CodecError("game_listen_failed");
#ifdef _WIN32
    int address_size = sizeof(address);
#else
    socklen_t address_size = sizeof(address);
#endif
    if (::getsockname(listener.value,reinterpret_cast<sockaddr*>(&address),&address_size) != 0) throw CodecError("game_getsockname_failed");
    bound_port_.store(ntohs(address.sin_port));
    if (log_) log_("game_transport_listening port=" + std::to_string(bound_port()));
    std::map<Socket,std::unique_ptr<Peer>> peers;
    std::uint64_t next_connection = 1;
    try {
        while (!stopping_.load()) {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(listener.value,&readable);
            auto maximum = listener.value;
            for (const auto& [socket,peer] : peers) {
                static_cast<void>(peer);
                FD_SET(socket,&readable);
                if (socket > maximum) maximum = socket;
            }
            timeval timeout{0,100000};
#ifdef _WIN32
            const auto ready = ::select(0,&readable,nullptr,nullptr,&timeout);
#else
            const auto ready = ::select(maximum+1,&readable,nullptr,nullptr,&timeout);
#endif
            if (ready < 0) throw CodecError("game_select_failed");
            if (FD_ISSET(listener.value,&readable)) {
                const auto socket = ::accept(listener.value,nullptr,nullptr);
                if (socket == invalid_socket) throw CodecError("game_accept_failed");
                OwnedSocket accepted(socket);
                const auto connection_id = next_connection++;
                const auto peer_log = [sink = log_,connection_id](const std::string& line) {
                    if (sink) sink("connection_id=" + std::to_string(connection_id) + " " + line);
                };
                if (peers.size() >= 32) peer_log("game_connection_rejected reason=capacity");
                else {
                    try {
                        configure_peer(socket);
                        auto peer = std::make_unique<Peer>(std::move(accepted),options_.version,factory_(),
                            std::chrono::steady_clock::now()+options_.admission_timeout,peer_log);
                        peers.emplace(socket,std::move(peer));
                        peer_log("game_connection_accepted");
                    } catch (const std::exception& error) {
                        peer_log("game_connection_closed reason=" + std::string(error.what()));
                    }
                }
            }
            for (auto item = peers.begin(); item != peers.end();) {
                auto& peer = *item->second;
                std::string reason;
                if (FD_ISSET(item->first,&readable)) {
                    try {
                        std::array<std::uint8_t,8192> input{};
                        const auto count = recv(item->first,reinterpret_cast<char*>(input.data()),static_cast<int>(input.size()),0);
                        if (count <= 0) reason = count == 0 ? "peer_closed" : "game_receive_failed";
                        else {
                            for (const auto& response : peer.session.feed(View(input).first(static_cast<std::size_t>(count)))) {
                                send_bytes(item->first,response);
                                peer.session.sent(response);
                            }
                            if (peer.session.state() == GameState::departing)
                                reason = "game_leave_completed";
                        }
                    } catch (const std::exception& error) { reason = error.what(); }
                    catch (...) { reason = "game_request_unknown_exception"; }
                }
                if (reason.empty() && peer.session.state() == GameState::awaiting_admission &&
                    std::chrono::steady_clock::now() >= peer.admission_deadline) reason = "game_admission_timeout";
                if (reason.empty()) ++item;
                else { peer.finish(std::move(reason)); item = peers.erase(item); }
            }
            for (auto item = peers.begin(); item != peers.end();) {
                auto& peer = *item->second;
                std::string reason;
                try {
                    for (const auto& response : peer.session.poll()) {
                        send_bytes(item->first,response);
                        peer.session.sent(response);
                    }
                } catch (const std::exception& error) { reason = error.what(); }
                catch (...) { reason = "game_poll_unknown_exception"; }
                if (reason.empty()) ++item;
                else { peer.finish(std::move(reason)); item = peers.erase(item); }
            }
        }
    } catch (...) {
        for (auto& [socket,peer] : peers) { static_cast<void>(socket); peer->finish("service_failed"); }
        throw;
    }
    for (auto& [socket,peer] : peers) { static_cast<void>(socket); peer->finish("service_stopped"); }
    if (log_) log_("game_transport_stopped");
}
}
