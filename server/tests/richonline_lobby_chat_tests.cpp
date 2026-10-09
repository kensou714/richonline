#include "richonline_lobby_chat.hpp"
#include "server_lobby_adapter.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
void put(Bytes& bytes,std::size_t offset,std::uint32_t value) {
    for(std::size_t i=0;i<4;++i) bytes.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
Frame message(std::uint32_t actor,std::uint32_t target,std::uint32_t scope,Bytes text) {
    text.push_back(0);
    Bytes bytes;
    for(const auto value:{2U,2U,actor,target,scope,static_cast<std::uint32_t>(text.size()),0U}) append_le(bytes,value,4);
    bytes.insert(bytes.end(),text.begin(),text.end());
    return {15,std::move(bytes)};
}
void router_boundaries() {
    const std::vector<RichonlineChatPeer> peers{{1,101,0,10},{2,102,0,10},{3,103,0,11},{4,104,1,10}};
    const auto channel=message(101,0,0,{'0','0',0xb4,0xfa,0xb8,0xd5});
    auto result=richonline_lobby_chat(1,channel,peers);
    check(result.rejection.empty() && result.deliveries.size()==3,"channel boundaries");
    for(const auto& item:result.deliveries) check(item.recipient!=4 && item.frame.payload==channel.payload,"CP950 or channel leaked");
    const auto room=message(101,10,1,{'1','0','h','i'});
    result=richonline_lobby_chat(1,room,peers);
    check(result.deliveries.size()==2 && result.deliveries[0].recipient==1 && result.deliveries[1].recipient==2,"room boundary");
    const auto whisper=message(101,103,4,{'2','0','s','e','c','r','e','t'});
    result=richonline_lobby_chat(1,whisper,peers);
    check(result.deliveries.size()==2 && result.deliveries[0].recipient==1 && result.deliveries[1].recipient==3,"private boundary or echo");
    check(richonline_lobby_chat(1,message(101,101,4,{'2','0','x'}),peers).deliveries.size()==1,"self whisper duplicated");
    const auto rejected=[&](Frame frame) { const auto value=richonline_lobby_chat(1,frame,peers);check(!value.rejection.empty() && value.deliveries.empty(),"invalid chat relayed"); };
    rejected(message(102,0,0,{'0','0','x'}));
    rejected(message(101,1,0,{'0','0','x'}));
    rejected(message(101,11,1,{'1','0','x'}));
    rejected(message(101,104,4,{'2','0','x'}));
    rejected(message(101,102,5,{'2','0','x'}));
    rejected(message(101,102,4,{'2','0','[','g','m',']','x'}));
    rejected(message(101,102,4,{'2','0','[','x',']'}));
    rejected(message(101,0,0,{'1','0','x'}));
    rejected(message(101,0,0,{'0','0',0xb4}));
    rejected(message(101,0,0,{'0','0','x',0,'y'}));
    auto malformed=channel;malformed.payload.pop_back();rejected(malformed);
    malformed=channel;put(malformed.payload,20,0xffffffffU);rejected(malformed);
    malformed=channel;put(malformed.payload,24,1);rejected(malformed);
    malformed=channel;put(malformed.payload,4,0);rejected(malformed);
    auto long_text=Bytes(400,'a');long_text[0]='0';long_text[1]='0';rejected(message(101,0,0,long_text));
    check(!richonline_lobby_chat(999,channel,peers).rejection.empty(),"unadmitted sender");
    const std::vector<RichonlineChatPeer> left{{1,101,0,std::nullopt},{2,102,0,10}};
    check(!richonline_lobby_chat(1,room,left).rejection.empty(),"departed room still sends");
    const std::vector<RichonlineChatPeer> wide{{1,0x10001,0x10002,0x10003}};
    check(richonline_lobby_chat(1,message(0x10001,0x10002,0,{'0','0','x'}),wide).deliveries.size()==1,
        "full-width actor or channel truncated");
    check(richonline_lobby_chat(1,message(0x10001,0x10003,1,{'1','0','x'}),wide).deliveries.size()==1,
        "full-width room truncated");
}
BootstrapBlobs fixture() {
    BootstrapBlobs blobs{};
    blobs.provenance="Isolated chat pipeline fixture; opaque fields are not protocol claims";
    blobs.game_capacity=8;blobs.player_capacity=100;blobs.room_unknown_prefix=0x12345678;
    blobs.setting_text="14";blobs.stage_progress={1,1,2,0};
    const auto bits=std::bit_cast<std::uint64_t>(2.5);
    for(std::size_t i=0;i<8;++i) blobs.unknown_completion[20+i]=static_cast<std::uint8_t>(bits>>(i*8));
    return blobs;
}
std::vector<Frame> decode(const std::vector<Bytes>& packets) {
    std::vector<Frame> frames;
    for(const auto& packet:packets) frames.push_back(decode_frame(packet,{Channel::lobby_s2c,219,ClientVersion::richonline}));
    return frames;
}
std::vector<Frame> feed(RichLobbySession& session,const Frame& frame) {
    return decode(session.feed(encode_frame(frame,{Channel::lobby_c2s,219,ClientVersion::richonline})));
}
void enter(RichLobbySession& session,const char* name,std::uint32_t actor) {
    static_cast<void>(session.start());
    static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
    Bytes login(144);std::copy_n(name,std::char_traits<char>::length(name),login.begin()+12);login[76]='p';
    static_cast<void>(feed(session,{58,login}));
    Bytes role;append_le(role,actor,4);static_cast<void>(feed(session,{34,role}));
    static_cast<void>(feed(session,{7,{0,0,0,0}}));
}
void encrypted_adapter_pipeline() {
    const auto base=std::filesystem::temp_directory_path()/("richonline-chat-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(base);
    Storage storage(base/"isolated.sqlite3");
    const auto create=[&](const char* name) {return storage.dispatch("accounts.create",{{"username",name},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();};
    const auto first=create("chat-first"),second=create("chat-second"),third=create("chat-third");
    std::string logs;
    ServerLobbyAdapter adapter(storage,fixture(),[&](const std::string& event,const nlohmann::json& value) {logs+=event+value.dump();});
    RichLobbySession a(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());
    RichLobbySession b(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());
    RichLobbySession c(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());
    enter(a,"chat-first",first);enter(b,"chat-second",second);enter(c,"chat-third",third);
    static_cast<void>(a.poll());static_cast<void>(b.poll());static_cast<void>(c.poll());
    auto request=message(first,0,0,{'0','0',0xb4,0xfa});
    const auto echo=feed(a,request),broadcast=decode(b.poll()),other=decode(c.poll());
    check(echo.size()==1 && broadcast.size()==1 && other.size()==1,"encrypted channel deliveries");
    check(echo[0].wire_type==15 && broadcast[0].payload==request.payload && other[0].payload==request.payload,"encrypted bytes changed");
    request=message(first,second,4,{'2','0','S','E','C','R','E','T','X'});
    check(feed(a,request).size()==1,"private echo absent");
    check(decode(b.poll()).at(0).payload==request.payload && c.poll().empty(),"private leak");
    b.finish();static_cast<void>(a.poll());static_cast<void>(c.poll());
    const auto unavailable=feed(a,request);
    check(unavailable.size()==1 && unavailable[0].wire_type==0xffffffffU &&
        unavailable[0].payload.size()==9 && read_le(View(unavailable[0].payload).first(4))==15,
        "unavailable target has no failure completion");
    check(a.state()==LobbyState::authenticated,"business rejection disconnected sender");
    request=message(first,0,0,{'0','0','o','k'});
    check(feed(a,request).size()==1 && decode(c.poll()).at(0).payload==request.payload,"chat did not recover after rejection");
    check(logs.find("SECRETX")==std::string::npos,"private text logged");
    a.finish();c.finish();
}
}
int main() {
    try {router_boundaries();encrypted_adapter_pipeline();std::cout<<"richonline_lobby_chat_tests ok\n";return 0;}
    catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
