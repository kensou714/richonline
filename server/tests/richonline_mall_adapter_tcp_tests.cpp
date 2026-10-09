#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "server_lobby_adapter.hpp"
#include <sqlite3.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <thread>

namespace {
using namespace richnet;
using Json=nlohmann::json;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class Action>void rejects(Action action,const char* reason){try{action();}catch(const std::runtime_error& error){check(std::string_view(error.what())==reason,"wrong rejection reason");return;}throw std::runtime_error("expected rejection");}
std::int64_t now(){return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
Bytes bytes(std::string_view text){return {text.begin(),text.end()};}
Frame scalar(std::uint32_t type,std::uint32_t value){Bytes payload;append_le(payload,value,4);return {type,std::move(payload)};}
Frame selection(std::int32_t mode){return scalar(16,static_cast<std::uint32_t>(mode));}
Frame purchase(std::uint32_t key){Bytes payload;for(const auto value:std::array<std::uint32_t,4>{0,1,key,1})append_le(payload,value,4);return {18,std::move(payload)};}
Frame activation(std::uint32_t mode,std::uint32_t key){auto frame=scalar(63,mode);append_le(frame.payload,key,4);return frame;}
double number(View bytes){check(bytes.size()==8,"double width");std::uint64_t bits=0;for(std::size_t i=0;i<8;++i)bits|=static_cast<std::uint64_t>(bytes[i])<<(8*i);return std::bit_cast<double>(bits);}
void failure(const Frame& frame,std::uint32_t request){check(frame.wire_type==0xffffffffU&&frame.payload.size()==9&&frame.payload.back()==0&&read_le(View(frame.payload).first(4))==request&&read_le(View(frame.payload).subspan(4,4))==static_cast<std::uint32_t>(-13),"mall refusal envelope");}
RichonlineMallCompatibilityPolicy policy(RichonlineInventoryDateVersion version=RichonlineInventoryDateVersion::original_2005){return {0xffffffffU,0x12345678U,-13,"Isolated TCP fixture: NEW77 ignores word0/word2; date mode is explicit",version,version==RichonlineInventoryDateVersion::compat_2021_v1?std::string(richonline_inventory_compatibility_id):std::string{}};}
BootstrapBlobs fixture(bool enabled=true,RichonlineInventoryDateVersion version=RichonlineInventoryDateVersion::original_2005){
    BootstrapBlobs blobs{};blobs.provenance="Isolated mall TCP fixture; no opaque byte business meaning is asserted";blobs.game_capacity=8;blobs.player_capacity=100;blobs.setting_text="14";blobs.stage_progress={1,1,2,0};
    const auto bits=std::bit_cast<std::uint64_t>(2.5);for(std::size_t i=0;i<8;++i)blobs.unknown_completion[20+i]=static_cast<std::uint8_t>(bits>>(8*i));
    for(std::uint32_t key=0;key<3;++key){ChannelCatalogEntry channel{};channel.key=key;channel.name_utf8="channel"+std::to_string(key);channel.room_capacity=8;channel.player_capacity=100;channel.max_level=20;channel.max_gold=1000000;blobs.channels.push_back(channel);}
    if(enabled)blobs.richonline_mall_policy=policy(version);return blobs;
}
std::shared_ptr<const RichonlineMallCatalog> catalog(){return std::make_shared<const RichonlineMallCatalog>(RichonlineMallCatalog::parse(bytes(
    "[PROP]\nindx=13\nname=PRODUCT_PRIVATE_PERMANENT\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\npriceLJ=3\nscore=30\n"
    "[PROP]\nindx=14\nname=Timed\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\npriceLJ=1\ndayJ=30\n"
    "[PROP]\nindx=17\nname=Activate\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\npriceLJ=1\njhdbJ=2\nbeanJ=5\njhDayJ=0\n"
    "[PROP]\nindx=18\nname=Restart\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\npriceLJ=4\nscore=40\n"),bytes("[F_J]\nprop=13\n[F_J]\nprop=14\n[F_J]\nprop=17\n[F_J]\nprop=18\n")));}
std::uint32_t account(Storage& storage,const char* username){const auto record=storage.dispatch("accounts.create",{{"username",username},{"password","p"}}).at("account");const auto role=record.at("role_id").get<std::uint32_t>();storage.dispatch("accounts.update",{{"role_id",role},{"expected",{{"coins",record.at("coins")},{"gold",record.at("gold")}}},{"changes",{{"coins",100.0},{"gold",1000.0}}},{"reason","isolated mall TCP balances"}});return role;}
void sql(const std::filesystem::path& path,const char* command){sqlite3* db=nullptr;const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture database open");const auto result=sqlite3_exec(db,command,nullptr,nullptr,nullptr);sqlite3_close(db);check(result==SQLITE_OK,"fixture SQL failed");}
std::int64_t sql_integer(const std::filesystem::path& path,const char* query){sqlite3* db=nullptr;const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"query database open");sqlite3_stmt* statement=nullptr;const auto prepared=sqlite3_prepare_v2(db,query,-1,&statement,nullptr);if(prepared!=SQLITE_OK){sqlite3_close(db);throw std::runtime_error("fixture query prepare");}const auto step=sqlite3_step(statement);const auto result=step==SQLITE_ROW?sqlite3_column_int64(statement,0):0;sqlite3_finalize(statement);sqlite3_close(db);check(step==SQLITE_ROW,"fixture query row");return result;}
struct Server {
    std::mutex mutex;std::condition_variable changed;bool listening=false;std::string logs;std::exception_ptr failure;
    ServerLobbyAdapter adapter;RichLobbyService service;std::thread worker;
    Server(Storage& storage,BootstrapBlobs blobs,std::shared_ptr<const RichonlineMallCatalog> products):
        adapter(storage,std::move(blobs),[this](const std::string& event,const Json& data){const std::lock_guard lock(mutex);logs+=event+data.dump()+'\n';}),
        service({"127.0.0.1",0,local_lobby_handshake()},[this]{return adapter.callbacks();},[this](const std::string& line){const std::lock_guard lock(mutex);logs+=line+'\n';if(line.starts_with("lobby_listening")){listening=true;changed.notify_all();}}){
        if(products)adapter.set_mall_catalog(std::move(products));worker=std::thread([this]{try{service.run();}catch(...){failure=std::current_exception();}});
        std::unique_lock lock(mutex);if(!changed.wait_for(lock,std::chrono::seconds(3),[this]{return listening;})){lock.unlock();stop();throw std::runtime_error("mall listener unavailable");}
    }
    ~Server(){service.stop();if(worker.joinable())worker.join();}
    void stop(){service.stop();if(worker.joinable())worker.join();if(failure)std::rethrow_exception(failure);}
    std::string log_snapshot(){const std::lock_guard lock(mutex);return logs;}
};
struct Client {
    SOCKET socket=INVALID_SOCKET;std::int32_t key;
    Client(Server& server,int exponent,std::string_view username):key(modpow_signed32(64,exponent,251)){
        socket=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);check(socket!=INVALID_SOCKET,"client socket");const DWORD timeout=3000;check(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout))==0,"client timeout");
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(server.service.bound_port());check(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1&&::connect(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"client connect");
        static_cast<void>(read(20));send_encoded(encode_frame(scalar(759,static_cast<std::uint32_t>(modpow_signed32(5,exponent,251))),{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline}));
        Bytes login(144);std::copy(username.begin(),username.end(),login.begin()+12);login[76]='p';send({58,std::move(login)});check(frame().wire_type==67,"native role catalog");const auto result=frame();check(result.wire_type==1,"native login result");const auto count=read_le(View(result.payload).subspan(4,4));for(std::uint32_t i=0;i<count;++i)check(frame().wire_type==3,"native channel catalog");
    }
    ~Client(){close();}
    void close(){if(socket!=INVALID_SOCKET){closesocket(socket);socket=INVALID_SOCKET;}}
    void send_encoded(View bytes){while(!bytes.empty()){check(bytes.size()<=static_cast<std::size_t>(std::numeric_limits<int>::max()),"send bound");const auto sent=::send(socket,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0);check(sent>0,"client send");bytes=bytes.subspan(static_cast<std::size_t>(sent));}}
    void send(const Frame& frame){send_encoded(encode_frame(frame,{Channel::lobby_c2s,key,ClientVersion::richonline}));}
    Bytes read(std::size_t count){Bytes bytes(count);std::size_t position=0;while(position<count){check(count-position<=static_cast<std::size_t>(std::numeric_limits<int>::max()),"read bound");const auto got=recv(socket,reinterpret_cast<char*>(bytes.data()+position),static_cast<int>(count-position),0);check(got>0,"client receive");position+=static_cast<std::size_t>(got);}return bytes;}
    Frame frame(){auto bytes=read(8);const auto total=read_le(View(bytes).subspan(4,4));check(total>=8&&total<=max_frame_total,"client frame total");const auto body=read(total-8);bytes.insert(bytes.end(),body.begin(),body.end());return decode_frame(bytes,{Channel::lobby_s2c,key,ClientVersion::richonline});}
    bool quiet(){fd_set readset;FD_ZERO(&readset);FD_SET(socket,&readset);timeval timeout{0,80000};const auto result=select(0,&readset,nullptr,nullptr,&timeout);check(result>=0,"select failed");return result==0;}
    std::vector<Frame> enter(std::uint32_t role,std::uint32_t channel){send(scalar(34,role));check(frame().wire_type==70,"role selection");send(scalar(7,channel));std::vector<Frame> result;for(std::size_t i=0;i<64;++i){result.push_back(frame());if(result.back().wire_type==30)return result;}throw std::runtime_error("channel bootstrap did not finish");}
};
const Frame& find(const std::vector<Frame>& frames,std::uint32_t wire){const auto it=std::find_if(frames.begin(),frames.end(),[&](const auto& frame){return frame.wire_type==wire;});check(it!=frames.end(),"bootstrap frame missing");return *it;}
void profile(const Frame& frame,std::uint32_t role,double coins,double gold,std::uint32_t score){check(frame.wire_type==7&&frame.payload.size()==272&&read_le(View(frame.payload).first(4))==role&&read_le(View(frame.payload).subspan(76,4))==score&&number(View(frame.payload).subspan(80,8))==coins&&number(View(frame.payload).subspan(88,8))==gold,"authoritative profile7 order/contents");}
std::uint32_t granted(const Frame& frame){check(frame.wire_type==77&&frame.payload.size()==12&&read_le(View(frame.payload).first(4))==0xffffffffU&&read_le(View(frame.payload).subspan(8,4))==0x12345678U,"verified77 configured cursor words");return read_le(View(frame.payload).subspan(4,4));}
void original_tcp(const std::filesystem::path& root){
    Storage storage(root/"original.sqlite3");const auto a=account(storage,"MallA"),b=account(storage,"MallB");sql(storage.database_path(),"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES('MallA',1073745937,0);");const auto products=catalog();
    rejects([&]{ServerLobbyAdapter compat(storage,fixture(true,RichonlineInventoryDateVersion::compat_2021_v1));},"inventory_date_database_mode_mismatch");
    {Server server(storage,fixture(),products);Client first(server,3,"MallA"),second(server,5,"MallB");
        first.send(purchase(0x100d));failure(first.frame(),18);first.enter(a,0);second.enter(b,1);check(first.key!=second.key,"TCP sessions share encryption key");
        first.send(purchase(0x100d));failure(first.frame(),18);first.send(selection(-1));check(first.quiet(),"selection16 invented ACK");second.send(purchase(0x100d));failure(second.frame(),18);
        first.send(purchase(0x100d));profile(first.frame(),a,97,1000,30);check(granted(first.frame())==0x100d,"permanent owned key");check(second.quiet(),"purchase leaked across channels");
        first.send(selection(-1));first.send(purchase(0x100d));failure(first.frame(),18);
        first.send(selection(-1));first.send({16,{1}});check(first.quiet(),"malformed16 invented ACK");first.send(purchase(0x1012));failure(first.frame(),18);
        first.send(selection(-1));auto malformed=purchase(0x1012);malformed.payload.push_back(0);first.send(malformed);failure(first.frame(),18);first.send(purchase(0x1012));failure(first.frame(),18);
        first.send(selection(-2));first.send(purchase(0x100d));failure(first.frame(),18);first.send(selection(-1));first.send(purchase(0x100e));failure(first.frame(),18);
        second.send(activation(2,0x40001011));failure(second.frame(),63);first.send({63,{1}});failure(first.frame(),63);
        first.send(activation(2,0x40001011));const auto activated=first.frame();check(activated.wire_type==213&&activated.payload.size()==20&&read_le(View(activated.payload).first(4))==0x40001011&&read_le(View(activated.payload).subspan(4,4))==0x1011&&read_le(View(activated.payload).subspan(8,4))==2&&number(View(activated.payload).subspan(12,8))==5,"activation213 real old/new/currency/charge");profile(first.frame(),a,97,995,30);
        second.send(selection(-1));second.send(purchase(0x100d));profile(second.frame(),b,97,1000,30);check(granted(second.frame())==0x100d,"session purchase namespace collision");
        const auto logs=server.log_snapshot();check(logs.find("PRODUCT_PRIVATE_PERMANENT")==std::string::npos&&logs.find("MallA")==std::string::npos&&logs.find("MallB")==std::string::npos,"mall request private data logged");check(logs.find("mall_selection16_size_invalid")!=std::string::npos&&logs.find("mall_purchase_without_selection")!=std::string::npos&&logs.find("inventory_date_year_unrepresentable")!=std::string::npos,"exact communication failure diagnostic missing");server.stop();
    }
    check(sql_integer(storage.database_path(),"SELECT count(*) FROM metadata WHERE key='inventory_date_version'")==0,"startup tagged original database implicitly");
    {Server restarted(storage,fixture(),products);Client client(restarted,7,"MallA");const auto initial=client.enter(a,0);profile(find(initial,7),a,97,995,30);const auto& inventory=find(initial,2);check(read_le(View(inventory.payload).first(4))==2,"reconnect lost committed inventory");client.send(selection(-1));client.send(purchase(0x1012));profile(client.frame(),a,93,995,70);check(granted(client.frame())==0x1012,"server restart reused operation namespace");restarted.stop();}
}
void disabled_tcp(const std::filesystem::path& root){
    Storage storage(root/"disabled.sqlite3");const auto actor=account(storage,"Disabled");for(const auto enabled:{false,true}){Server server(storage,fixture(enabled),enabled?std::shared_ptr<const RichonlineMallCatalog>{}:catalog());Client client(server,3,"Disabled");client.enter(actor,0);client.send(selection(-1));check(client.quiet(),"disabled16 invented ACK");client.send(purchase(0x100d));failure(client.frame(),18);client.send(activation(2,0x40001011));failure(client.frame(),63);check(storage.roles_for_username("Disabled")[0].at("coins")==100.0,"disabled mall charged");rejects([&]{server.adapter.set_mall_catalog(catalog());},"richonline_mall_catalog_set_after_listening");server.stop();}
}
void compat_real_resource_tcp(const std::filesystem::path& root,const std::filesystem::path& client_root){
    Storage storage(root/"compat.sqlite3");const auto actor=account(storage,"Compat");sql(storage.database_path(),"INSERT INTO metadata(key,value) VALUES('inventory_date_version','richonline-inventory-date-2021-v1');");
    rejects([&]{ServerLobbyAdapter old(storage,fixture(false));},"inventory_date_database_mode_mismatch");
    const auto products=std::make_shared<const RichonlineMallCatalog>(RichonlineMallCatalog::load(client_root));const auto& product=products->purchasable(0x1004);const auto term=product.term[0];check(term.years+term.months+term.days>0,"real timed product fixture changed");
    {Server server(storage,fixture(true,RichonlineInventoryDateVersion::compat_2021_v1),products);Client client(server,3,"Compat");client.enter(actor,0);const auto before=now();client.send(selection(-1));client.send(purchase(0x1004));profile(client.frame(),actor,100-product.price[0],1000,product.score);const auto key=granted(client.frame());const auto after=now();check((key&0xffffU)==0x1004,"real timed grant identity/currency changed");const auto date=decode_richonline_inventory_date(key,RichonlineInventoryDateVersion::compat_2021_v1);const auto expires=sql_integer(storage.database_path(),"SELECT expires_at FROM lobby_inventory WHERE username='Compat';");check(expires>=richonline_inventory_calendar_expiry(before,term.years,term.months,term.days)&&expires<=richonline_inventory_calendar_expiry(after,term.years,term.months,term.days)&&date==richonline_inventory_utc_date(expires),"real timed expiry truncated or fabricated");client.close();server.stop();}
    {Server restarted(storage,fixture(true,RichonlineInventoryDateVersion::compat_2021_v1),products);Client client(restarted,5,"Compat");const auto initial=client.enter(actor,0);const auto& inventory=find(initial,2);check(inventory.payload.size()==12&&read_le(View(inventory.payload).first(4))==1,"compat inventory did not survive reconnect");const auto date=decode_richonline_inventory_date(read_le(View(inventory.payload).subspan(4,4)),RichonlineInventoryDateVersion::compat_2021_v1);check(date&&date->year>=2026,"compat inventory was emitted as original epoch");restarted.stop();}
}
std::filesystem::path resource_root(){const auto library=LoadLibraryW(L"shell32.dll");check(library!=nullptr,"load command line parser");using Parse=LPWSTR* (WINAPI*)(LPCWSTR,int*);const auto parse=reinterpret_cast<Parse>(GetProcAddress(library,"CommandLineToArgvW"));if(!parse){FreeLibrary(library);throw std::runtime_error("command line parser unavailable");}int count=0;auto arguments=parse(GetCommandLineW(),&count);if(!arguments){FreeLibrary(library);throw std::runtime_error("command line parse failed");}const std::filesystem::path path=count==2?arguments[1]:L"";LocalFree(arguments);FreeLibrary(library);check(!path.empty(),"real NEW client resource root argument required");return path;}
}
int main(){try{const auto root=std::filesystem::temp_directory_path()/("mall-adapter-tcp-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(root);original_tcp(root);disabled_tcp(root);compat_real_resource_tcp(root,resource_root());std::cout<<"PASS encrypted NEW mall TCP, profile7/77 and213/profile7 order, exact rejection/reconnect/session isolation, original/compat DB guard and actual timed resource expiry\n";return 0;}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
