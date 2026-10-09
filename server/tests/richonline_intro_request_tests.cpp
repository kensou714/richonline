#include "richonline_intro_request.hpp"
#include "server_lobby_adapter.hpp"
#include "auxiliary.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sqlite3.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <thread>

namespace {
using namespace richnet;
void check(bool value,const char* reason) {if(!value)throw std::runtime_error(reason);}
BootstrapBlobs fixture() {
    BootstrapBlobs blobs{};blobs.provenance="isolated intro pipeline test";
    blobs.game_capacity=8;blobs.player_capacity=100;blobs.setting_text="14";blobs.stage_progress={1,1,2,0};
    const auto bits=std::bit_cast<std::uint64_t>(2.5);
    for(std::size_t i=0;i<8;++i)blobs.unknown_completion[20+i]=static_cast<std::uint8_t>(bits>>(8*i));
    return blobs;
}
std::vector<Frame> feed(RichLobbySession& session,const Frame& request) {
    const auto packets=session.feed(encode_frame(request,{Channel::lobby_c2s,219,ClientVersion::richonline}));
    std::vector<Frame> frames;for(const auto& packet:packets)frames.push_back(decode_frame(packet,{Channel::lobby_s2c,219,ClientVersion::richonline}));
    return frames;
}
Frame intro(std::string_view text) {auto bytes=client_text(text);bytes.push_back(0);return {50,std::move(bytes)};}
struct TcpIntro {
    std::mutex mutex;std::condition_variable changed;unsigned listeners=0;std::exception_ptr error;
    AuxiliaryService service;std::thread thread;
    explicit TcpIntro(RichonlineAuxiliaryStore& store):service([&] {
        AuxiliaryOptions options;options.http_port=0;options.black_port=0;options.intro_port=0;
        options.intro_response=[&store](View request){return store.intro_response(request);};return options;
    }(),[this](const AuxiliaryEvent& event){const std::lock_guard lock(mutex);if(event.event=="auxiliary_listening")++listeners;changed.notify_all();}),
        thread([this]{try{service.run();}catch(...){const std::lock_guard lock(mutex);error=std::current_exception();changed.notify_all();}}){}
    ~TcpIntro(){service.stop();if(thread.joinable())thread.join();}
    void ready(){std::unique_lock lock(mutex);check(changed.wait_for(lock,std::chrono::seconds(5),[&]{return listeners==3||error;}),"intro listener timeout");if(error)std::rethrow_exception(error);}
    Bytes read(const RichonlineAuxiliaryName& name) {
        const auto socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);check(socket!=INVALID_SOCKET,"intro socket");
        struct Close {SOCKET socket;~Close(){closesocket(socket);}} close{socket};
        const DWORD timeout=3000;check(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"intro timeout");
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(service.bound_intro_port());inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
        check(connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"intro connect");
        Bytes request{13,10};append_le(request,0,4);append_le(request,32,4);request.insert(request.end(),name.begin(),name.end());
        std::size_t sent=0;while(sent<request.size()){const auto n=send(socket,reinterpret_cast<const char*>(request.data()+sent),static_cast<int>(request.size()-sent),0);check(n>0,"intro send");sent+=static_cast<std::size_t>(n);}
        Bytes response;std::array<std::uint8_t,512> buffer{};
        for(;;){const auto n=recv(socket,reinterpret_cast<char*>(buffer.data()),static_cast<int>(buffer.size()),0);check(n>=0,"intro recv");if(n==0)break;response.insert(response.end(),buffer.begin(),buffer.begin()+n);}
        return response;
    }
};
void sql(const std::filesystem::path& path,const char* command){
    sqlite3* db=nullptr;const auto encoded=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(encoded.c_str()),&db)==SQLITE_OK,"fixture database");
    const auto status=sqlite3_exec(db,command,nullptr,nullptr,nullptr);sqlite3_close(db);check(status==SQLITE_OK,"fixture trigger");
}
}
int main(){try{
    WSADATA data{};check(WSAStartup(MAKEWORD(2,2),&data)==0,"winsock");struct Cleanup{~Cleanup(){WSACleanup();}}cleanup;
    const auto path=std::filesystem::temp_directory_path()/("intro-request-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    Storage accounts(path);const auto record=accounts.dispatch("accounts.create",{{"username","IntroPlayer"},{"password","p"}}).at("account");
    const auto id=record.at("role_id").get<std::uint32_t>();
    std::string logs;ServerLobbyAdapter adapter(accounts,fixture(),[&](const std::string& event,const nlohmann::json& values){logs+=event+values.dump();});
    RichLobbySession session(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());
    static_cast<void>(session.start());static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
    Bytes login(144);const std::string username="IntroPlayer";std::copy(username.begin(),username.end(),login.begin()+12);login[76]='p';static_cast<void>(feed(session,{58,login}));
    check(feed(session,intro("unselected")).at(0).wire_type==0xffffffffU,"unselected intro accepted");
    Bytes selected;append_le(selected,id,4);static_cast<void>(feed(session,{34,selected}));static_cast<void>(feed(session,{7,{0,0,0,0}}));
    RichonlineAuxiliaryStore store(path);TcpIntro server(store);server.ready();const auto name=richonline_auxiliary_name(username);
    const std::string text="測試SECRETX";
    check(feed(session,intro(text)).empty(),"intro success fabricated ACK");
    check(server.read(name)==encode_richonline_intro(name,client_text(text)),"encrypted write did not reach independent intro TCP read");
    check(store.introduction(name).revision==1,"intro revision missing");
    check(feed(session,intro(text)).empty()&&store.introduction(name).revision==1,"same intro not idempotent");
    for(const auto& payload:{Bytes{},Bytes{'x'},Bytes{'x',0,'y',0},Bytes{0x81,0},Bytes(401,'x')}){
        const auto reply=feed(session,{50,payload});check(reply.size()==1&&reply[0].wire_type==0xffffffffU&&reply[0].payload.size()==9&&
            read_le(View(reply[0].payload).first(4))==50,"invalid intro missing rejection");
        check(session.state()==LobbyState::authenticated&&store.introduction(name).text_utf8==text,"invalid intro changed account or disconnected");
    }
    sql(path,"CREATE TRIGGER reject_intro_audit BEFORE INSERT ON audit WHEN NEW.field='introduction' BEGIN SELECT RAISE(ABORT,'fixture'); END;");
    check(feed(session,intro("Rollback")).at(0).wire_type==0xffffffffU,"transaction failure not reported");
    check(server.read(name)==encode_richonline_intro(name,client_text(text)),"failed audit did not rollback");
    sql(path,"DROP TRIGGER reject_intro_audit;");
    check(feed(session,{50,{1,0}}).empty(),"empty sentinel rejected");check(server.read(name)==encode_richonline_intro(name,{}),"empty sentinel not persisted");
    const auto wrong=richonline_intro_request(accounts,store,"Other",id,intro("wrong"));check(!wrong.rejection.empty(),"cross account intro saved");
    check(accounts.roles_for_username(username).at(0)==record,"intro changed role finances");
    check(logs.find("SECRETX")==std::string::npos,"intro body logged");session.finish();
    std::cout<<"PASS NEW encrypted wire50 save, independent intro TCP read, empty sentinel, reject recovery, ownership, audit rollback\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
