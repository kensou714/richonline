#include "auxiliary.hpp"
#include "richonline_auxiliary_store.hpp"
#include "storage.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
struct Harness {
    std::mutex mutex;
    std::condition_variable changed;
    unsigned listeners=0;
    std::exception_ptr error;
    AuxiliaryService service;
    std::thread thread;
    explicit Harness(AuxiliaryOptions options):service(std::move(options),[this](const AuxiliaryEvent& event){
        const std::lock_guard lock(mutex);
        if(event.event=="auxiliary_listening") ++listeners;
        changed.notify_all();
    }),thread([this]{try{service.run();}catch(...){const std::lock_guard lock(mutex);error=std::current_exception();changed.notify_all();}}){}
    ~Harness(){service.stop();if(thread.joinable())thread.join();}
    void ready(){std::unique_lock lock(mutex);check(changed.wait_for(lock,std::chrono::seconds(5),[&]{return listeners==3||error;}),"listeners timeout");if(error)std::rethrow_exception(error);}
};
Bytes exchange(std::uint16_t port,View request){
    const auto socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    check(socket!=INVALID_SOCKET,"socket failed");
    struct Close{SOCKET value;~Close(){closesocket(value);}} close{socket};
    const DWORD timeout=3000;
    check(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"timeout failed");
    sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(port);inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr);
    check(connect(socket,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0,"connect failed");
    // Exercise real TCP accumulation with a split between the intro header/name.
    check(send(socket,reinterpret_cast<const char*>(request.data()),7,0)==7,"first send failed");
    check(send(socket,reinterpret_cast<const char*>(request.data()+7),static_cast<int>(request.size()-7),0)==static_cast<int>(request.size()-7),"second send failed");
    Bytes response;std::array<std::uint8_t,512> buffer{};
    for(;;){const auto count=recv(socket,reinterpret_cast<char*>(buffer.data()),static_cast<int>(buffer.size()),0);check(count>=0,"receive failed");if(count==0)break;response.insert(response.end(),buffer.begin(),buffer.begin()+count);}
    return response;
}
}
int main(){try{
    WSADATA data{};check(WSAStartup(MAKEWORD(2,2),&data)==0,"winsock failed");
    struct Cleanup{~Cleanup(){WSACleanup();}} cleanup;
    const auto path=std::filesystem::absolute("intro-tcp-test-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    Storage accounts(path);
    const auto role=accounts.dispatch("accounts.create",{{"username","Player"},{"password","test"}}).at("account");
    RichonlineAuxiliaryStore store(path);
    store.save_introduction("Player",role.at("role_id").get<std::int64_t>(),"Real profile text",0,"tcp test");
    AuxiliaryOptions options;options.http_port=0;options.black_port=0;options.intro_port=0;
    options.intro_response=[&](View input){return store.intro_response(input);};
    Harness server(std::move(options));server.ready();
    Bytes request{13,10};append_le(request,0,4);append_le(request,32,4);
    const auto name=richonline_auxiliary_name("Player");request.insert(request.end(),name.begin(),name.end());
    const auto response=exchange(server.service.bound_intro_port(),request);
    check(response==encode_richonline_intro(name,client_text("Real profile text")),"intro TCP response mismatch");
    auto malformed=request;malformed[6]=31;
    check(exchange(server.service.bound_intro_port(),malformed).empty(),"malformed got fake success");
    check(exchange(server.service.bound_intro_port(),request)==response,"bad auxiliary request killed listener");
    std::cout<<"PASS NEW intro independent TCP listener, real SQLite response, fragmentation, bad request isolation\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
