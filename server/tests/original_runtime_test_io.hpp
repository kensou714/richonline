#pragma once
#include "codec.hpp"
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace original_runtime_test {
using namespace richnet;
inline void check(bool value,const char* code) { if (!value) throw std::runtime_error(code); }
struct Network {
    Network() { WSADATA data{}; check(WSAStartup(MAKEWORD(2,2),&data) == 0,"winsock_start_failed"); }
    ~Network() { WSACleanup(); }
};
struct Socket {
    SOCKET value = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    explicit Socket(std::uint16_t port) {
        check(value != INVALID_SOCKET,"tcp_socket_failed");
        try {
            const DWORD timeout = 5000;
            for (const auto option : {SO_SNDTIMEO,SO_RCVTIMEO})
                check(setsockopt(value,SOL_SOCKET,option,reinterpret_cast<const char*>(&timeout),sizeof(timeout)) == 0,
                      "tcp_timeout_failed");
            sockaddr_in target{};
            target.sin_family = AF_INET; target.sin_port = htons(port);
            check(inet_pton(AF_INET,"127.0.0.1",&target.sin_addr) == 1,"tcp_address_failed");
            check(::connect(value,reinterpret_cast<sockaddr*>(&target),sizeof(target)) == 0,"tcp_connect_failed");
        } catch (...) { closesocket(value); throw; }
    }
    ~Socket() { closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    void raw(View bytes) {
        while (!bytes.empty()) {
            const auto count = ::send(value,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);
            check(count > 0,"tcp_send_failed"); bytes = bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    void send(const Frame& frame,std::optional<std::int32_t> key = 219) {
        raw(encode_frame(frame,{Channel::lobby_c2s,key,ClientVersion::legacy}));
    }
    Bytes read(std::size_t size) {
        Bytes bytes(size);
        for (std::size_t offset=0;offset<size;) {
            const auto count = recv(value,reinterpret_cast<char*>(bytes.data()+offset),static_cast<int>(size-offset),0);
            check(count > 0,"tcp_receive_failed"); offset += static_cast<std::size_t>(count);
        }
        return bytes;
    }
    Frame receive() {
        auto bytes = read(8);
        const auto size = read_le(View(bytes).subspan(4,4));
        check(size >= 8 && size <= 65536,"tcp_response_length_invalid");
        const auto payload = read(size-8);
        bytes.insert(bytes.end(),payload.begin(),payload.end());
        return decode_frame(bytes,{Channel::lobby_s2c,219,ClientVersion::legacy});
    }
};
inline std::string http(std::uint16_t port) {
    Socket client(port);
    const std::string request = "GET /gameinfo/RichNetLogin.txt HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client.raw(View(reinterpret_cast<const std::uint8_t*>(request.data()),request.size()));
    std::string response;
    char bytes[1024];
    int count = 0;
    while ((count = recv(client.value,bytes,sizeof(bytes),0)) > 0) response.append(bytes,static_cast<std::size_t>(count));
    check(count == 0,"http_receive_failed");
    return response;
}
inline Bytes black_request(std::uint32_t type) {
    Bytes packet{13,10}; append_le(packet,type,4); append_le(packet,type == 1 ? 96 : 64,4);
    packet.resize(type == 1 ? 106 : 74,0);
    packet[10] = 'A';
    std::fill(packet.begin()+42,packet.begin()+74,'a');
    if (type == 1) packet[74] = 'B';
    return packet;
}
inline Bytes black_reply(Socket& socket) {
    const auto header = socket.read(10);
    check(header[0] == 13 && header[1] == 10,"black_response_magic_wrong");
    const auto size = read_le(View(header).subspan(6,4));
    check(size <= 4096,"black_response_size_invalid");
    return socket.read(size);
}
}
