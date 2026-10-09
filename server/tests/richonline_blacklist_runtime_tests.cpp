#include "lobby_runtime.hpp"
#include "richonline_auxiliary_store.hpp"
#include "richonline_ranking.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sqlite3.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>

namespace {
using namespace richnet;
using Json=nlohmann::json;
void check(bool value,const char* reason) {if(!value) throw std::runtime_error(reason);}
struct Network {
    Network(){WSADATA data{};check(WSAStartup(MAKEWORD(2,2),&data)==0,"winsock startup");}
    ~Network(){WSACleanup();}
};
struct Socket {
    SOCKET value=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    explicit Socket(std::uint16_t port){
        check(value!=INVALID_SOCKET,"socket create");
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(port);
        inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
        if(::connect(value,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0){closesocket(value);throw std::runtime_error("socket connect");}
        const DWORD timeout=3000;
        check(setsockopt(value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"socket timeout");
    }
    ~Socket(){closesocket(value);}
    Socket(const Socket&)=delete;
    Socket& operator=(const Socket&)=delete;
    void send(View bytes){
        while(!bytes.empty()){
            const auto count=::send(value,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);
            check(count>0,"socket send");bytes=bytes.subspan(static_cast<std::size_t>(count));
        }
    }
    Bytes receive(std::optional<std::size_t> expected={}){
        Bytes result;std::array<std::uint8_t,2048> buffer{};
        while(!expected || result.size()<*expected){
            const auto capacity=expected ? std::min(buffer.size(),*expected-result.size()):buffer.size();
            const auto count=::recv(value,reinterpret_cast<char*>(buffer.data()),static_cast<int>(capacity),0);
            check(count>=0,"socket receive failed or timeout");
            if(count==0){check(!expected || result.size()==*expected,"socket closed early");break;}
            result.insert(result.end(),buffer.begin(),buffer.begin()+count);check(result.size()<8192,"response too large");
        }
        return result;
    }
};
struct Logs {
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<std::pair<std::string,Json>> entries;
    void add(const std::string& event,const Json& data){
        const std::lock_guard lock(mutex);entries.emplace_back(event,data);changed.notify_all();
    }
    void wait_reason(const std::string& reason){
        std::unique_lock lock(mutex);
        check(changed.wait_for(lock,std::chrono::seconds(3),[&]{
            return std::any_of(entries.begin(),entries.end(),[&](const auto& entry){return entry.second.value("reason","")==reason;});
        }),"expected runtime diagnostic missing");
    }
};
Json fixture(){
    Json config{{"provenance","Synthetic isolated blacklist runtime fixture, not production defaults"},
        {"game_capacity",8},{"player_capacity",100},{"stage_progress",{1,1,2,0}},{"setting_text","14"},
        {"network",{{"bind_host","127.0.0.1"},{"advertised_host","127.0.0.1"},{"lobby_port",0},{"http_port",0},{"black_port",0}}}};
    for(const auto& [name,size]:std::initializer_list<std::pair<const char*,std::size_t>>{
        {"unknown_channel_record_hex",80},{"unknown_role_record_hex",208},{"unknown_profile_record_hex",272},
        {"unknown_login_result_hex",16},{"unknown_identity_record_hex",16},{"unknown_empty_list_hex",4},{"unknown_bank_config_hex",32}})
        config[name]=std::string(size*2,'0');
    config["unknown_completion_hex"]=std::string(40,'0')+"000000000000f03f";
    return config;
}
void save(const std::filesystem::path& path,const Json& config){std::ofstream file(path);file<<config;check(file.good(),"fixture save");}
Bytes black(std::uint32_t type,bool enabled=true){
    Bytes packet{13,10};append_le(packet,type,4);
    const auto size=type==4 ? 97U:(type==1 || type==2 ? 96U:64U);
    append_le(packet,size,4);packet.resize(size+10,0);
    const std::string owner="RuntimeSynthetic",digest="0123456789abcdef0123456789abcdef",target="BlackTarget";
    std::copy(owner.begin(),owner.end(),packet.begin()+10);std::copy(digest.begin(),digest.end(),packet.begin()+42);
    if(type==1 || type==2 || type==4)std::copy(target.begin(),target.end(),packet.begin()+74);
    if(type==4)packet[106]=enabled ? 1:0;
    return packet;
}
Bytes transact(std::uint16_t port,const Bytes& packet){Socket socket(port);socket.send(View(packet).first(3));socket.send(View(packet).subspan(3));return socket.receive();}
void list_record(View packet,bool enabled){
    check(packet.size()==86,"list record and terminator size");
    check(read_le(packet.subspan(2,4))==0 && read_le(packet.subspan(6,4))==33,"list framing");
    const std::string expected="BlackTarget";
    check(std::equal(expected.begin(),expected.end(),packet.begin()+10),"persisted target name");
    check(packet[42]==(enabled ? 1:0),"persisted enabled flag");
    check(packet[43]==13 && packet[44]==10 && packet[53]==0,"list terminator");
}
void mutation_status(View packet,std::uint32_t type,std::uint32_t status){
    check(packet.size()==46 && read_le(packet.subspan(2,4))==type && read_le(packet.subspan(6,4))==36 &&
        read_le(packet.subspan(10,4))==status,"mutation response");
}
void sql(const std::filesystem::path& path,const char* statement){
    sqlite3* db=nullptr;const auto encoded=path.u8string();
    check(sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&db,SQLITE_OPEN_READWRITE,nullptr)==SQLITE_OK,"fixture database open");
    const auto code=sqlite3_exec(db,statement,nullptr,nullptr,nullptr);sqlite3_close(db);check(code==SQLITE_OK,"fixture SQL");
}
void authenticate(Socket& socket){
    check(socket.receive(20).size()==20,"lobby handshake");
    socket.send(encode_frame({759,{0x71,0,0,0}},{Channel::lobby_c2s,{},ClientVersion::richonline}));
    Bytes payload(144,0);const std::string username="blacklist-runtime",password="isolated-password";
    std::copy(username.begin(),username.end(),payload.begin()+12);std::copy(password.begin(),password.end(),payload.begin()+76);
    socket.send(encode_frame({58,payload},{Channel::lobby_c2s,219,ClientVersion::richonline}));
    StreamDecoder decoder({Channel::lobby_s2c,219,ClientVersion::richonline});
    const auto response=decoder.feed(socket.receive(332));
    check(response.size()==3 && response[0].wire_type==67,"actual SQLite login failed");
}
void scenario(const std::filesystem::path& root){
    Storage storage(root/"accounts.sqlite3");
    const auto account=storage.dispatch("accounts.create",{{"username","blacklist-runtime"},{"password","isolated-password"}}).at("account");
    RichonlineAuxiliaryStore introductions(storage.database_path());
    introductions.save_introduction("blacklist-runtime",account.at("role_id").get<std::int64_t>(),
        "Runtime persisted introduction",0,"isolated runtime test");
    Bytes intro_request{13,10}; append_le(intro_request,0,4); append_le(intro_request,32,4);
    const auto intro_name=richonline_auxiliary_name("blacklist-runtime");
    intro_request.insert(intro_request.end(),intro_name.begin(),intro_name.end());
    const auto intro_reply=encode_richonline_intro(intro_name,client_text("Runtime persisted introduction"));
    RichonlineRankingStore rankings(storage.database_path());
    Bytes ranking_request{13,10}; append_le(ranking_request,1,4); append_le(ranking_request,1,4);
    const auto ranking_reply=rankings.response(ranking_request);
    check(ranking_reply && ranking_reply->size()==56,"runtime ranking fixture must contain actual account");
    const auto path=root/"bootstrap.json",database=root/"richonline-blacklist.sqlite3";
    auto config=fixture(); config["network"]["intro_port"]=0; config["network"]["inquiry_port"]=0; save(path,config);Logs logs;
    const auto sink=[&](const std::string& event,const Json& data){logs.add(event,data);};
    {
        LobbyRuntime runtime(storage,path,sink);
        const auto status=runtime.status();
        check(status.at("blackReady")==true && status.at("lobbyReady")==true,"runtime not ready");
        check(status.at("introReady")==true &&
            transact(status.at("introPort").get<std::uint16_t>(),intro_request)==intro_reply,"runtime intro wiring failed");
        check(status.at("inquiryReady")==true &&
            transact(status.at("inquiryPort").get<std::uint16_t>(),ranking_request)==*ranking_reply,"runtime inquiry wiring failed");
        const auto port=status.at("blackPort").get<std::uint16_t>();
        Socket lobby(status.at("lobbyPort").get<std::uint16_t>());authenticate(lobby);
        check(transact(port,black(0)).size()==43,"new runtime empty list");
        mutation_status(transact(port,black(1)),1,0);list_record(transact(port,black(0)),true);
        check(transact(port,black(4,false)).empty(),"toggle must not reply");list_record(transact(port,black(0)),false);
        const auto unsupported=transact(port,black(3));
        check(unsupported.size()==14 && read_le(View(unsupported).subspan(10,4))==0xffffffffU,"type3 must be explicit unsupported");
        check(runtime.status().at("authenticatedSessions")==1,"auxiliary operation terminated lobby session");
        check(std::filesystem::exists(database) && !std::filesystem::exists(root/"original-blacklist.sqlite3"),"NEW isolated database path");
        runtime.stop();
    }
    {
        LobbyRuntime runtime(storage,path,sink);const auto port=runtime.status().at("blackPort").get<std::uint16_t>();
        check(transact(runtime.status().at("introPort").get<std::uint16_t>(),intro_request)==intro_reply,
            "runtime introduction not persistent after restart");
        check(transact(runtime.status().at("inquiryPort").get<std::uint16_t>(),ranking_request)==*ranking_reply,
            "runtime ranking not persistent after restart");
        list_record(transact(port,black(0)),false);
        sql(database,"PRAGMA ignore_check_constraints=ON; UPDATE blacklist SET enabled=2;");
        check(transact(port,black(0)).empty(),"corrupt row received false success");
        logs.wait_reason("blacklist_database_row_invalid");
        check(runtime.status().at("blackReady")==true && runtime.status().at("httpReady")==true &&
            !runtime.status().contains("listenerFailure"),"single corrupt request killed runtime");
        sql(database,"UPDATE blacklist SET enabled=0;");list_record(transact(port,black(0)),false);
        mutation_status(transact(port,black(2)),2,0);check(transact(port,black(0)).size()==43,"remove not visible");
        mutation_status(transact(port,black(2)),2,2);
        runtime.stop();
    }
    {
        LobbyRuntime runtime(storage,path,sink);
        check(transact(runtime.status().at("blackPort").get<std::uint16_t>(),black(0)).size()==43,"delete not persistent after restart");
        runtime.stop();
    }
    config["network"]["bind_host"]="0.0.0.0";save(path,config);
    bool rejected=false;
    try{LobbyRuntime exposed(storage,path,sink);}catch(const CodecError& error){rejected=std::string(error.what())=="richonline_blacklist_authenticated_binding_required";}
    check(rejected,"remote blacklist must require authenticated binding");
}
}
int main(){
    try{
        Network network;
        const auto root=std::filesystem::absolute("blacklist-runtime-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        scenario(root);std::filesystem::remove_all(root);
        std::cout<<"PASS NEW blacklist actual LobbyRuntime TCP: mutations, restart, corruption isolation, live lobby session, loopback gate\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
