#include "lobby.hpp"

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
void close_socket(Socket value) { if (value != invalid_socket) closesocket(value); }
struct NetworkRuntime {
    NetworkRuntime() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw CodecError("lobby_winsock_start_failed");
    }
    ~NetworkRuntime() { WSACleanup(); }
};
#else
using Socket = int;
constexpr Socket invalid_socket = -1;
void close_socket(Socket value) { if (value != invalid_socket) ::close(value); }
struct NetworkRuntime {};
#endif
struct OwnedSocket {
    Socket value = invalid_socket;
    explicit OwnedSocket(Socket socket) : value(socket) {}
    ~OwnedSocket() { close_socket(value); }
    OwnedSocket(const OwnedSocket&) = delete;
    OwnedSocket& operator=(const OwnedSocket&) = delete;
    OwnedSocket(OwnedSocket&& other) noexcept : value(std::exchange(other.value, invalid_socket)) {}
};

void send_bytes(Socket socket, View data) {
    while (!data.empty()) {
        const auto sent = ::send(socket, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0);
        if (sent <= 0) throw CodecError("lobby_send_failed");
        data = data.subspan(static_cast<std::size_t>(sent));
    }
}

void configure_peer(Socket socket) {
#ifdef _WIN32
    const DWORD timeout = 5000;
    if (::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0)
        throw CodecError("lobby_send_timeout_setup_failed");
#else
    const timeval timeout{5, 0};
    if (::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        throw CodecError("lobby_send_timeout_setup_failed");
#endif
}

struct Peer {
    std::uint64_t id;
    OwnedSocket socket;
    RichLobbySession session;
    bool authenticated = false;
    Peer(std::uint64_t connection_id, OwnedSocket&& accepted, const LobbyOptions& options, const LobbyCallbacks& callbacks, const LobbyLogSink& log)
        : id(connection_id), socket(std::move(accepted)), session(options, callbacks, [log, connection_id](const std::string& message) {
            if (log) log("connection_id=" + std::to_string(connection_id) + " " + message);
        }) {}
};
}

RichLobbyService::RichLobbyService(LobbyOptions options, LobbyCallbacks callbacks, LobbyLogSink log)
    : RichLobbyService(std::move(options), [callbacks = std::move(callbacks)] { return callbacks; }, std::move(log)) {}

RichLobbyService::RichLobbyService(LobbyOptions options, LobbyCallbackFactory factory, LobbyLogSink log)
    : options_(std::move(options)), callback_factory_(std::move(factory)), log_(std::move(log)) {
    if (!callback_factory_) throw CodecError("lobby_callback_factory_required");
}

void RichLobbyService::run() {
    RichLobbySession preflight(options_, {});
    static_cast<void>(preflight.start());
    const NetworkRuntime network;
    const OwnedSocket listener(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (listener.value == invalid_socket) throw CodecError("lobby_socket_create_failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(options_.port);
    if (inet_pton(AF_INET, options_.host.c_str(), &address.sin_addr) != 1)
        throw CodecError("lobby_invalid_bind_address");
    if (::bind(listener.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
        throw CodecError("lobby_bind_failed");
    if (::listen(listener.value, 32) != 0) throw CodecError("lobby_listen_failed");
#ifdef _WIN32
    int address_size = sizeof(address);
#else
    socklen_t address_size = sizeof(address);
#endif
    if (::getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &address_size) != 0)
        throw CodecError("lobby_getsockname_failed");
    bound_port_.store(ntohs(address.sin_port));
    if (log_) log_("lobby_listening port=" + std::to_string(bound_port()));
    std::map<Socket, std::unique_ptr<Peer>> peers;
    std::uint64_t next_connection = 1;
    try {
        while (!stopping_.load()) {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(listener.value, &readable);
            auto maximum = listener.value;
            for (const auto& [socket, peer] : peers) {
                static_cast<void>(peer);
                FD_SET(socket, &readable);
                if (socket > maximum) maximum = socket;
            }
            timeval timeout{0, 200000};
#ifdef _WIN32
            const auto ready = ::select(0, &readable, nullptr, nullptr, &timeout);
#else
            const auto ready = ::select(maximum + 1, &readable, nullptr, nullptr, &timeout);
#endif
            if (ready < 0) throw CodecError("lobby_select_failed");
            if (FD_ISSET(listener.value, &readable)) {
                const auto socket = ::accept(listener.value, nullptr, nullptr);
                if (socket == invalid_socket) throw CodecError("lobby_accept_failed");
                if (peers.size() >= 32) {
                    close_socket(socket);
                    if (log_) log_("lobby_connection_rejected reason=capacity");
                } else {
                    const auto connection_id = next_connection++;
                    OwnedSocket accepted(socket);
                    try {
                        auto peer = std::make_unique<Peer>(connection_id, std::move(accepted), options_, callback_factory_(), log_);
                        configure_peer(socket);
                        const auto handshake=peer->session.start();
                        send_bytes(socket,handshake);peer->session.sent(handshake);
                        peers.emplace(socket, std::move(peer));
                    } catch (const std::exception& error) {
                        if (log_) log_("connection_id=" + std::to_string(connection_id) + " lobby_connection_closed reason=" + error.what());
                    }
                }
            }
            for (auto item = peers.begin(); item != peers.end();) {
                const auto socket = item->first;
                auto& session = item->second->session;
                bool closed = false;
                try {
                    if (FD_ISSET(socket, &readable)) {
                        std::array<std::uint8_t, 8192> input{};
                        const auto count = ::recv(socket, reinterpret_cast<char*>(input.data()), static_cast<int>(input.size()), 0);
                        if (count <= 0) {
                            session.finish();
                            closed = true;
                            if (log_) log_("connection_id=" + std::to_string(item->second->id) + " lobby_connection_closed reason=peer_closed");
                        } else {
                            const auto responses = session.feed(View(input).first(static_cast<std::size_t>(count)));
                            if (!item->second->authenticated && session.state() == LobbyState::authenticated) {
                                item->second->authenticated = true;
                                authenticated_sessions_.fetch_add(1);
                            }
                            for (const auto& response : responses) {send_bytes(socket,response);session.sent(response);}
                            if (session.state() == LobbyState::closed) {
                                closed = true;
                                if (log_) log_("connection_id=" + std::to_string(item->second->id) + " lobby_connection_closed reason=session_closed");
                            }
                        }
                    }
                    if (!closed)
                        for (const auto& notification : session.poll()) {send_bytes(socket,notification);session.sent(notification);}
                } catch (const std::exception& error) {
                    closed = true;
                    if (log_) log_("connection_id=" + std::to_string(item->second->id) + " lobby_connection_closed reason=" + error.what());
                } catch (...) {
                    closed = true;
                    if (log_) log_("connection_id=" + std::to_string(item->second->id) + " lobby_connection_closed reason=unknown_exception");
                }
                if (closed) {
                    if (item->second->authenticated) authenticated_sessions_.fetch_sub(1);
                    item = peers.erase(item);
                } else ++item;
            }
        }
    } catch (...) {
        peers.clear();
        authenticated_sessions_.store(0);
        bound_port_.store(0);
        throw;
    }
    peers.clear();
    authenticated_sessions_.store(0);
    bound_port_.store(0);
    if (log_) log_("lobby_stopped");
}

}
