#include "auxiliary.hpp"
#include "richonline_ranking.hpp"
#include "richonline_game_ledger.hpp"
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
    struct Rejection { std::string reason; std::optional<std::uint32_t> type; std::size_t bytes; };
    std::vector<Rejection> rejections;
    std::exception_ptr error;
    AuxiliaryService service;
    std::thread thread;
    explicit Harness(AuxiliaryOptions options):service(std::move(options),[this](const AuxiliaryEvent& event){
        const std::lock_guard lock(mutex);
        if(event.event=="auxiliary_listening") ++listeners;
        if(event.event=="auxiliary_connection_closed" && event.service==AuxiliaryKind::inquiry)
            rejections.push_back({std::string(event.reason),event.wire_type,event.request_bytes});
        changed.notify_all();
    }),thread([this]{try{service.run();}catch(...){const std::lock_guard lock(mutex);error=std::current_exception();changed.notify_all();}}){}
    ~Harness(){service.stop();if(thread.joinable())thread.join();}
    void ready(){std::unique_lock lock(mutex);check(changed.wait_for(lock,std::chrono::seconds(5),[&]{return listeners==3||error;}),"listeners timeout");if(error)std::rethrow_exception(error);}
    void rejected(std::size_t index,const char* reason,std::uint32_t type,std::size_t minimum_bytes){
        std::unique_lock lock(mutex);
        check(changed.wait_for(lock,std::chrono::seconds(5),[&]{return rejections.size()>index||error;}),"rejection log timeout");
        if(error)std::rethrow_exception(error);
        const auto& entry=rejections.at(index);
        check(entry.reason==reason,"wrong rejection reason");
        check(entry.type==type,"wrong rejected wire type");
        check(entry.bytes>=minimum_bytes && entry.bytes<=42,"wrong rejected request length");
    }
};
Bytes exchange(std::uint16_t port,View request,bool expect_rejection=false){
    const auto socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    check(socket!=INVALID_SOCKET,"socket failed");
    struct Close{SOCKET value;~Close(){closesocket(value);}} close{socket};
    const DWORD timeout=3000;
    check(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"timeout failed");
    sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(port);inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr);
    check(connect(socket,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0,"connect failed");
    // Split the inquiry category DWORD. An unknown type is rejected as soon as
    // the first fragment arrives; closing with unread data can produce a reset.
    check(send(socket,reinterpret_cast<const char*>(request.data()),7,0)==7,"first send failed");
    const auto tail=send(socket,reinterpret_cast<const char*>(request.data()+7),static_cast<int>(request.size()-7),0);
    if(tail==SOCKET_ERROR && expect_rejection && WSAGetLastError()==WSAECONNRESET)return {};
    check(tail==static_cast<int>(request.size()-7),"second send failed");
    Bytes response;std::array<std::uint8_t,512> buffer{};
    for(;;){
        const auto count=recv(socket,reinterpret_cast<char*>(buffer.data()),static_cast<int>(buffer.size()),0);
        if(count==SOCKET_ERROR){
            const auto error=WSAGetLastError();
            if(expect_rejection && response.empty() && error==WSAECONNRESET)break;
            throw std::runtime_error("receive failed: "+std::to_string(error));
        }
        if(count==0)break;
        response.insert(response.end(),buffer.begin(),buffer.begin()+count);
    }
    return response;
}
}
int main(){try{
    WSADATA data{};check(WSAStartup(MAKEWORD(2,2),&data)==0,"winsock failed");
    struct Cleanup{~Cleanup(){WSACleanup();}} cleanup;
    const auto path=std::filesystem::absolute("ranking-tcp-test-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    Storage accounts(path);
    const auto role=accounts.dispatch("accounts.create",{{"username","Player"},{"password","test"}}).at("account");
    RichonlineRankingStore store(path);
    std::array<std::uint32_t,21> thresholds{};
    for(std::size_t index=0;index<thresholds.size();++index)thresholds[index]=static_cast<std::uint32_t>(index)*100;
    const GameSettlementReward reward{0,0,0,{}};
    const auto role_id=role.at("role_id").get<std::int64_t>();
    RichonlineGameLedger ledger({{1000,500,0,0}});
    ledger.adjust(0,ledger.snapshot(0),{-100,100,0,0});
    ledger.adjust(0,ledger.snapshot(0),{73,0,0,0});
    const auto income=ledger.income_snapshot(0);
    accounts.settle_game("Player",role_id,{"tcp-settlement","tcp-match","tcp-test",GameOutcome::win,0,{},
        {"isolated TCP test policy",reward,reward,reward,reward,thresholds,0},{},
        GameSettlementAchievement{RichonlineAchievement::cash_earned,income.earned_cash,richonline_cash_earned_policy,income.ledger_revision}});
    AuxiliaryOptions options;options.http_port=0;options.black_port=0;options.inquiry_port=0;
    options.inquiry_response=[&](View input){return store.response(input);};
    Harness server(std::move(options));server.ready();
    Bytes request{13,10};append_le(request,1,4);append_le(request,1,4);
    const auto response=exchange(server.service.bound_inquiry_port(),request);
    check(response==*store.response(request),"ranking TCP response mismatch");
    auto malformed=request;malformed[2]=3;
    check(exchange(server.service.bound_inquiry_port(),malformed,true).empty(),"unknown type got fake success");
    server.rejected(0,"richonline_inquiry_wire_type_unknown",3,7);
    auto category=request;category[6]=99;
    check(exchange(server.service.bound_inquiry_port(),category,true).empty(),"unknown category got fake success");
    server.rejected(1,"ranking_category_unknown",1,10);
    check(exchange(server.service.bound_inquiry_port(),request)==response,"bad auxiliary request killed listener");
    Bytes named{13,10};append_le(named,0,4);append_le(named,3,4);
    const auto name=richonline_auxiliary_name("Player");named.insert(named.end(),name.begin(),name.end());
    check(exchange(server.service.bound_inquiry_port(),named)==*store.response(named),"type0 TCP response mismatch");
    named[2]=2;
    check(exchange(server.service.bound_inquiry_port(),named)==*store.response(named),"type2 TCP response mismatch");
    named[6]=9;
    check(exchange(server.service.bound_inquiry_port(),named,true).empty(),"unrecorded category got fake success");
    server.rejected(2,"ranking_achievement_category_not_recorded",2,42);
    check(exchange(server.service.bound_inquiry_port(),request)==response,"achievement rejection killed listener");
    std::cout<<"PASS NEW inquiry TCP types0/1/2, settled real metrics, fragmentation and rejected-category socket isolation\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
