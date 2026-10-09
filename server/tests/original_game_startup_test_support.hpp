#pragma once

#include "original_game_startup.hpp"
#include "service.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string_view>
#include <thread>
#include <utility>

namespace original_startup_test {
using namespace richnet;
inline void require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
template<class Action> void rejects(Action action, const char* code) {
    try { action(); } catch (const CodecError& error) {
        require(std::string_view(error.what()) == code, "unexpected_startup_rejection");
        return;
    }
    throw std::runtime_error("expected_startup_rejection_missing");
}
struct Network {
    Network() { WSADATA data{}; require(WSAStartup(MAKEWORD(2,2),&data) == 0,"winsock_start_failed"); }
    ~Network() { WSACleanup(); }
};
struct Client {
    SOCKET socket = INVALID_SOCKET;
    explicit Client(std::uint16_t port) {
        socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        require(socket != INVALID_SOCKET,"socket_failed");
        const DWORD timeout = 2000;
        require(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) == 0,
                "receive_timeout_failed");
        sockaddr_in address{};
        address.sin_family = AF_INET; address.sin_port = htons(port);
        require(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr) == 1,"address_failed");
        require(connect(socket,reinterpret_cast<const sockaddr*>(&address),sizeof(address)) == 0,"connect_failed");
    }
    ~Client() { if (socket != INVALID_SOCKET) closesocket(socket); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    void send(View bytes) const {
        while (!bytes.empty()) {
            const auto count = ::send(socket,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);
            require(count > 0,"send_failed"); bytes = bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    Bytes read(std::size_t size) const {
        Bytes bytes(size);
        std::size_t position = 0;
        while (position < size) {
            const auto count = recv(socket,reinterpret_cast<char*>(bytes.data()+position),static_cast<int>(size-position),0);
            require(count > 0,"reply_missing"); position += static_cast<std::size_t>(count);
        }
        return bytes;
    }
    Bytes plain() const {
        auto packet = read(8);
        const auto size = read_le(View(packet).subspan(4,4));
        require(size >= 8 && size <= max_frame_total,"reply_size_invalid");
        const auto payload = read(size-8); packet.insert(packet.end(),payload.begin(),payload.end());
        const auto envelope = decode_envelope(decode_frame(packet,{Channel::game_s2c,{},ClientVersion::legacy}));
        require(envelope.inner_type == -123 && envelope.mode == -7 &&
                envelope.tail == std::array<std::uint8_t,4>{0x12,0x34,0x56,0x78},"response_metadata_lost");
        return decode_inner(envelope.encoded);
    }
    void closed() const {
        char byte{};
        const auto count = recv(socket,&byte,1,0);
        require(count == 0 || (count == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET),"peer_not_closed_or_extra_reply");
    }
};
struct Running {
    std::mutex mutex;
    std::condition_variable ready;
    bool listening = false;
    std::exception_ptr error;
    GameService service;
    std::thread thread;
    explicit Running(GameCallbackFactory factory)
        : service({"127.0.0.1",0,ClientVersion::legacy},std::move(factory),[this](const std::string& line) {
            if (line.starts_with("game_transport_listening")) {
                const std::lock_guard lock(mutex); listening = true; ready.notify_one();
            }
        }), thread([this] { try { service.run(); } catch (...) { error = std::current_exception(); } }) {
        std::unique_lock lock(mutex);
        if (!ready.wait_for(lock,std::chrono::seconds(5),[this] { return listening; })) {
            service.stop(); thread.join(); throw std::runtime_error("listener_not_ready");
        }
    }
    ~Running() { service.stop(); if (thread.joinable()) thread.join(); }
    void finish() { service.stop(); thread.join(); if (error) std::rethrow_exception(error); }
};
inline OriginalStartup startup(std::int16_t self = 25) {
    return {{0x3456,1.5,{2024,2,29,4},0,
        {{self,0x2345,3,{1,2,3,4,5,6,7,8,9,10},0xe5}},0xa7,{0xde,0xad}},
        {0x3456,0x1234ffff,3,{{0x12345678,0x23456789,0x3456789a}},{0xba,0xad}},
        {-123,-7,{0x12,0x34,0x56,0x78}}};
}
inline Bytes expected_init(std::uint8_t self = 25) {
    return {0,0x40,0x56,0x34,0,0,0,0,0,0,0xf8,0x3f,0xe8,7,2,29,4,1,0,0xa7,
        self,0,0x45,0x23,3,1,2,3,4,5,6,7,8,9,10,0xe5,0xde,0xad};
}
inline Bytes expected_snapshot() {
    return {4,0x40,0x56,0x34,0xff,0xff,0x34,0x12,3,0,0,0,
        0x78,0x56,0x34,0x12,0x89,0x67,0x45,0x23,0x9a,0x78,0x56,0x34,0xba,0xad};
}
inline const Bytes turn{0x10,0x40,0x56,0x34,0,0,0};
inline const Bytes opaque_result{0x11,0x40,0x56,0x34,0xd3,0x7f,0xa9,0xb8};
inline Bytes message(View plain) {
    return encode_frame(encode_envelope({0,-1,encode_inner(plain,Bytes(plain.size()+2,0xb1)),{0x76,0x45,0x32,0x19}}),
                        {Channel::game_c2s,{},ClientVersion::legacy});
}
inline Bytes ticket(const GameAdmission& admission) {
    return encode_frame(encode_game_admission(admission,ClientVersion::legacy),{Channel::game_c2s,{},ClientVersion::legacy});
}
inline GameAdmission admission_from_redirect(const Frame& redirect, std::uint32_t self) {
    require(redirect.wire_type == 22 && redirect.payload.size() == 18,"redirect_shape_invalid");
    const View payload(redirect.payload);
    require(payload[0] == 127 && payload[1] == 0 && payload[2] == 0 && payload[3] == 1,"redirect_host_invalid");
    GameAdmission result{9,13,self,{},read_le(payload.subspan(6,4)),std::array<std::uint32_t,2>{0,0}};
    std::copy(payload.begin()+10,payload.end(),result.opaque8.begin());
    require(encode_game_admission(result,ClientVersion::legacy).payload.size() == 32,"original_admission_not_32_bytes");
    return result;
}
struct Counts { std::atomic_int ready{0}; std::atomic_int actions{0}; std::atomic_int events{0}; std::atomic_int released{0}; };
inline OriginalGamePlan plan(Counts& counts, std::int16_t self = 25) {
    return {startup(self),[&counts] { ++counts.ready; return std::vector<Bytes>{turn}; },
        [&counts](View plain) {
            if (read_le(plain.first(2)) == 2) { ++counts.events; return std::vector<Bytes>{opaque_result}; }
            ++counts.actions; return std::vector<Bytes>{opaque_result,turn};
        },[&counts] { ++counts.released; }};
}
inline GameAdmission direct_admission() { return {9,13,25,{1,2,3,4,5,6,7,8},19,std::array<std::uint32_t,2>{0,0}}; }
inline GameCallbacks direct_callbacks(OriginalGamePlan value) {
    return make_original_game_callbacks([value = std::move(value)](const GameAdmission&) { return value; });
}
}
