#include "lobby.hpp"
#include "storage.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
struct TemporaryDirectory {
    const std::filesystem::path path = std::filesystem::temp_directory_path()/
        ("lobby-auth-failure-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    TemporaryDirectory() { check(std::filesystem::create_directory(path),"fixture_directory_collision"); }
    ~TemporaryDirectory() { std::error_code ignored; std::filesystem::remove_all(path,ignored); }
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
};
struct Socket {
    SOCKET value = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};
struct Server {
    RichLobbyService& service;
    std::exception_ptr failure;
    std::thread worker;
    explicit Server(RichLobbyService& target) : service(target),worker([this] {
        try { service.run(); } catch (...) { failure = std::current_exception(); }
    }) {}
    ~Server() { service.stop(); if (worker.joinable()) worker.join(); }
};
Bytes read_exact(SOCKET socket,std::size_t size) {
    Bytes output(size);
    for (std::size_t offset=0; offset<size;) {
        const auto count=recv(socket,reinterpret_cast<char*>(output.data()+offset),static_cast<int>(size-offset),0);
        check(count>0,"authentication_response_missing"); offset+=static_cast<std::size_t>(count);
    }
    return output;
}
void send_all(SOCKET socket,View bytes) {
    while (!bytes.empty()) {
        const auto count=send(socket,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);
        check(count>0,"fixture_send_failed"); bytes=bytes.subspan(static_cast<std::size_t>(count));
    }
}
void authentication_failure_closes_after_version_specific_response(ClientVersion version) {
    const auto profile=version==ClientVersion::richonline ? ClientProfile::richonline : ClientProfile::original;
    const TemporaryDirectory temporary;
    Storage storage(temporary.path/"accounts.sqlite3",profile);
    const auto before=storage.dispatch("accounts.create",{{"username","FailureFixture"},{"password","fixture-correct"}}).at("account");
    std::atomic_int verified{0}, success{0}, requested{0}, cleaned{0};
    std::mutex mutex; std::condition_variable changed; bool listening=false;
    std::vector<std::string> logs;
    LobbyCallbacks callbacks;
    callbacks.verify_credentials=[&](const std::string& username,View password) {
        ++verified; return storage.verify_credentials(username,password);
    };
    callbacks.login_responses=[&](const LobbyLogin&) { ++success; return std::vector<Frame>{{1,{1}}}; };
    callbacks.authenticated_request=[&](const LobbyLogin&,const Frame&) { ++requested; return std::vector<Frame>{}; };
    callbacks.disconnected=[&] { ++cleaned; };
    RichLobbyService service({"127.0.0.1",0,local_lobby_handshake(),version},callbacks,[&](const std::string& line) {
        const std::lock_guard lock(mutex); logs.push_back(line);
        if (line.starts_with("lobby_listening")) { listening=true; changed.notify_all(); }
    });
    Server server(service);
    { std::unique_lock lock(mutex); check(changed.wait_for(lock,std::chrono::seconds(5),[&] { return listening; }),"fixture_listener_missing"); }
    Socket socket; check(socket.value!=INVALID_SOCKET,"fixture_socket_failed");
    const DWORD timeout=3000;
    check(setsockopt(socket.value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"fixture_timeout_failed");
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(service.bound_port());
    check(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1,"fixture_address_failed");
    check(connect(socket.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"fixture_connect_failed");
    static_cast<void>(read_exact(socket.value,20));
    auto input=encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,version});
    Bytes payload(144,0);
    if (version==ClientVersion::legacy) payload[4]=132;
    constexpr std::string_view username="FailureFixture",password="fixture-incorrect";
    std::copy(username.begin(),username.end(),payload.begin()+12);
    std::copy(password.begin(),password.end(),payload.begin()+76);
    const auto login=encode_frame({58,payload},{Channel::lobby_c2s,219,version});
    input.insert(input.end(),login.begin(),login.end());
    input.insert(input.end(),login.begin(),login.end());
    const auto channel=encode_frame({34,{0,0,0,0}},{Channel::lobby_c2s,219,version});
    input.insert(input.end(),channel.begin(),channel.end());
    send_all(socket.value,input);
    if (version==ClientVersion::richonline) {
        auto packet=read_exact(socket.value,8);
        const auto size=read_le(View(packet).subspan(4,4));
        check(size>=8 && size<=max_frame_total,"authentication_response_length_invalid");
        const auto body=read_exact(socket.value,size-8); packet.insert(packet.end(),body.begin(),body.end());
        const auto response=decode_frame(packet,{Channel::lobby_s2c,219,version});
        check(response.wire_type==0xffffffffU && response.payload==Bytes{58,0,0,0,0x9b,0xff,0xff,0xff,0},
            "authentication_response_contract_wrong");
    }
    char byte{};
    check(recv(socket.value,&byte,1,0)==0,"rejected_session_not_closed_after_response");
    service.stop(); server.worker.join();
    if (server.failure) std::rethrow_exception(server.failure);
    check(verified==1 && success==0 && requested==0 && cleaned==1 && service.authenticated_sessions()==0,
        "authentication_failure_lifecycle_wrong");
    check(storage.roles_for_username("FailureFixture")==nlohmann::json::array({before}),"authentication_failure_changed_role");
    check(storage.verify_credentials("FailureFixture",View(reinterpret_cast<const std::uint8_t*>("fixture-correct"),15)),
        "authentication_failure_changed_password");
    check(std::none_of(logs.begin(),logs.end(),[](const auto& line) {
        return line.find("lobby_authenticated")!=line.npos || line.find("fixture-incorrect")!=line.npos ||
            line.find("fixture-correct")!=line.npos;
    }),"authentication_failure_leaked_success_or_password");
}
}
int main() {
    try {
        authentication_failure_closes_after_version_specific_response(ClientVersion::richonline);
        authentication_failure_closes_after_version_specific_response(ClientVersion::legacy);
        std::cout << "lobby authentication failure TCP tests PASS\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
