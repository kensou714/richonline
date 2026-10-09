#include "auxiliary_internal.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <chrono>
#include <limits>
#include <map>
#include <memory>
#include <utility>

namespace richnet {
namespace {
struct NetworkRuntime {
    NetworkRuntime() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw CodecError("auxiliary_winsock_start_failed");
    }
    ~NetworkRuntime() { WSACleanup(); }
};
struct OwnedSocket {
    SOCKET value;
    explicit OwnedSocket(SOCKET socket) : value(socket) {}
    ~OwnedSocket() { if (value != INVALID_SOCKET) closesocket(value); }
    OwnedSocket(const OwnedSocket&) = delete;
    OwnedSocket& operator=(const OwnedSocket&) = delete;
};
std::uint16_t listen(OwnedSocket& listener, const std::string& host, std::uint16_t port) {
    if (listener.value == INVALID_SOCKET) throw CodecError("auxiliary_socket_create_failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1)
        throw CodecError("auxiliary_invalid_bind_address");
    if (::bind(listener.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
        throw CodecError("auxiliary_bind_failed");
    if (::listen(listener.value, 32) != 0) throw CodecError("auxiliary_listen_failed");
    int size = sizeof(address);
    if (::getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size) != 0)
        throw CodecError("auxiliary_getsockname_failed");
    return ntohs(address.sin_port);
}
void send_all(SOCKET socket, View bytes) {
    while (!bytes.empty()) {
        const auto sent = ::send(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
        if (sent <= 0) throw CodecError("auxiliary_send_failed");
        bytes = bytes.subspan(static_cast<std::size_t>(sent));
    }
}
struct Peer {
    OwnedSocket socket;
    AuxiliaryKind kind;
    std::uint64_t id;
    Bytes input;
    std::chrono::steady_clock::time_point accepted = std::chrono::steady_clock::now();
    Peer(SOCKET value, AuxiliaryKind service, std::uint64_t connection) : socket(value), kind(service), id(connection) {}
};
}

AuxiliaryService::AuxiliaryService(AuxiliaryOptions options, AuxiliaryLogSink log)
    : options_(std::move(options)), log_(std::move(log)) {
    if (options_.capacity == 0 || options_.capacity > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
        options_.channel_id > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) || options_.lobby_port == 0)
        throw CodecError("auxiliary_channel_configuration_invalid");
    if (options_.intro_port.has_value() != static_cast<bool>(options_.intro_response))
        throw CodecError("auxiliary_intro_configuration_incomplete");
    if (options_.inquiry_port.has_value() != static_cast<bool>(options_.inquiry_response))
        throw CodecError("auxiliary_inquiry_configuration_incomplete");
}

void AuxiliaryService::run() {
    const NetworkRuntime network;
    in_addr advertised{};
    if (inet_pton(AF_INET, options_.advertised_host.c_str(), &advertised) != 1)
        throw CodecError("auxiliary_invalid_advertised_address");
    const auto emit = [&](const AuxiliaryEvent& event) { if (log_) log_(event); };
    OwnedSocket http(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    OwnedSocket black(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    OwnedSocket intro(options_.intro_port ? ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) : INVALID_SOCKET);
    OwnedSocket inquiry(options_.inquiry_port ? ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) : INVALID_SOCKET);
    std::map<SOCKET, std::unique_ptr<Peer>> peers;
    try {
        const auto http_port = listen(http, options_.bind_host, options_.http_port);
        const auto black_port = listen(black, options_.bind_host, options_.black_port);
        const auto intro_port = options_.intro_port ? listen(intro, options_.bind_host, *options_.intro_port) : 0;
        const auto inquiry_port = options_.inquiry_port ? listen(inquiry, options_.bind_host, *options_.inquiry_port) : 0;
        http_port_.store(http_port);
        black_port_.store(black_port);
        intro_port_.store(static_cast<std::uint16_t>(intro_port));
        inquiry_port_.store(static_cast<std::uint16_t>(inquiry_port));
        emit({"auxiliary_listening", AuxiliaryKind::http, 0, {}, std::nullopt, 0, 0, http_port});
        emit({"auxiliary_listening", AuxiliaryKind::black, 0, {}, std::nullopt, 0, 0, black_port});
        if (options_.intro_port)
            emit({"auxiliary_listening", AuxiliaryKind::intro, 0, {}, std::nullopt, 0, 0, static_cast<std::uint16_t>(intro_port)});
        if (options_.inquiry_port)
            emit({"auxiliary_listening", AuxiliaryKind::inquiry, 0, {}, std::nullopt, 0, 0, static_cast<std::uint16_t>(inquiry_port)});
        std::uint64_t next_id = 0;
        while (!stopping_.load()) {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(http.value, &readable);
            FD_SET(black.value, &readable);
            if (intro.value != INVALID_SOCKET) FD_SET(intro.value, &readable);
            if (inquiry.value != INVALID_SOCKET) FD_SET(inquiry.value, &readable);
            for (const auto& [socket, peer] : peers) {
                static_cast<void>(peer);
                FD_SET(socket, &readable);
            }
            timeval timeout{0, 100000};
            const auto ready = ::select(0, &readable, nullptr, nullptr, &timeout);
            if (ready < 0) throw CodecError("auxiliary_select_failed");
            const std::array listeners{std::pair{http.value, AuxiliaryKind::http}, std::pair{black.value, AuxiliaryKind::black},
                std::pair{intro.value, AuxiliaryKind::intro}, std::pair{inquiry.value, AuxiliaryKind::inquiry}};
            for (const auto& [listener, kind] : listeners) {
                if (listener == INVALID_SOCKET || !FD_ISSET(listener, &readable)) continue;
                const auto socket = ::accept(listener, nullptr, nullptr);
                if (socket == INVALID_SOCKET) throw CodecError("auxiliary_accept_failed");
                auto peer = std::make_unique<Peer>(socket, kind, ++next_id);
                if (peers.size() >= 32) {
                    emit({"auxiliary_connection_closed", kind, peer->id, "capacity_limit", std::nullopt, 0, 0, 0});
                    continue;
                }
                const DWORD send_timeout = 2000;
                if (::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&send_timeout), sizeof(send_timeout)) != 0)
                    throw CodecError("auxiliary_send_timeout_setup_failed");
                peers.emplace(socket, std::move(peer));
                emit({"auxiliary_connection_accepted", kind, next_id, {}, std::nullopt, 0, 0, 0});
            }
            for (auto item = peers.begin(); item != peers.end();) {
                auto& peer = *item->second;
                bool closed = false;
                std::optional<std::uint32_t> type;
                try {
                    if (std::chrono::steady_clock::now() - peer.accepted > std::chrono::seconds(5))
                        throw CodecError("auxiliary_request_timeout");
                    if (FD_ISSET(peer.socket.value, &readable)) {
                        std::array<std::uint8_t, 2048> chunk{};
                        const auto count = ::recv(peer.socket.value, reinterpret_cast<char*>(chunk.data()), static_cast<int>(chunk.size()), 0);
                        if (count <= 0) throw CodecError("auxiliary_peer_closed");
                        peer.input.insert(peer.input.end(), chunk.begin(), chunk.begin() + count);
                        const auto limit = peer.kind == AuxiliaryKind::http ? 8192U :
                            (peer.kind == AuxiliaryKind::intro || peer.kind == AuxiliaryKind::inquiry) ? 42U :
                            (options_.black_response ? 107U : 106U);
                        if (peer.input.size() > limit) throw CodecError("auxiliary_request_too_large");
                        if (peer.kind != AuxiliaryKind::http && peer.input.size() >= 6)
                            type = read_le(View(peer.input).subspan(2, 4));
                        const auto result = auxiliary_detail::response(peer.kind, peer.input, options_);
                        if (result) {
                            send_all(peer.socket.value, result->bytes);
                            emit({result->bytes.empty() ? "auxiliary_request_completed" : "auxiliary_response_sent", peer.kind, peer.id, result->reason,
                                  result->type, peer.input.size(), result->bytes.size()});
                            closed = true;
                        }
                    }
                } catch (const std::exception& error) {
                    emit({"auxiliary_connection_closed", peer.kind, peer.id, error.what(), type, peer.input.size()});
                    closed = true;
                }
                if (closed) item = peers.erase(item); else ++item;
            }
        }
    } catch (...) {
        http_port_.store(0);
        black_port_.store(0);
        intro_port_.store(0);
        inquiry_port_.store(0);
        throw;
    }
    http_port_.store(0);
    black_port_.store(0);
    intro_port_.store(0);
    inquiry_port_.store(0);
    emit({"auxiliary_stopped", AuxiliaryKind::http, 0, {}, std::nullopt, 0, 0, 0});
    emit({"auxiliary_stopped", AuxiliaryKind::black, 0, {}, std::nullopt, 0, 0, 0});
    if (options_.intro_port) emit({"auxiliary_stopped", AuxiliaryKind::intro, 0, {}, std::nullopt, 0, 0, 0});
    if (options_.inquiry_port) emit({"auxiliary_stopped", AuxiliaryKind::inquiry, 0, {}, std::nullopt, 0, 0, 0});
}

}
