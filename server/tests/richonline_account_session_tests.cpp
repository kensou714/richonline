#include "server_lobby_adapter.hpp"
#include <sqlite3.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) {if(!value)throw std::runtime_error(reason);}
Bytes amount(double value) {
    Bytes bytes;const auto bits=std::bit_cast<std::uint64_t>(value);
    for(std::size_t i=0;i<8;++i)bytes.push_back(static_cast<std::uint8_t>(bits>>(8*i)));
    return bytes;
}
Frame exchange(double value) {
    Bytes bytes;append_le(bytes,1,4);append_le(bytes,2,4);
    const auto tail=amount(value);bytes.insert(bytes.end(),tail.begin(),tail.end());return {42,std::move(bytes)};
}
BootstrapBlobs fixture(double ratio) {
    BootstrapBlobs blobs{};
    blobs.provenance="Isolated account encrypted session fixture; unused bytes are not protocol claims";
    blobs.game_capacity=8;blobs.player_capacity=100;blobs.room_unknown_prefix=0x12345678;
    blobs.setting_text="14";blobs.stage_progress={1,1,2,0};
    const auto rate=amount(ratio);std::copy(rate.begin(),rate.end(),blobs.unknown_completion.begin()+20);
    for(const auto& [offset,value]:std::initializer_list<std::pair<std::size_t,double>>{{8,10},{16,5},{24,1000}}) {
        const auto data=amount(value);std::copy(data.begin(),data.end(),blobs.unknown_bank_config.begin()+static_cast<std::ptrdiff_t>(offset));
    }
    return blobs;
}
std::vector<Frame> feed(RichLobbySession& session,const Frame& frame) {
    std::vector<Frame> frames;
    const auto encrypted=encode_frame(frame,{Channel::lobby_c2s,219,ClientVersion::richonline});
    // Fragment every packet across header and payload boundaries.
    for(std::size_t at=0;at<encrypted.size();) {
        const auto count=std::min(std::size_t{7},encrypted.size()-at);
        for(const auto& output:session.feed(View(encrypted).subspan(at,count)))
            frames.push_back(decode_frame(output,{Channel::lobby_s2c,219,ClientVersion::richonline}));
        at+=count;
    }
    return frames;
}
void enter(RichLobbySession& session,std::uint32_t actor) {
    check(!session.start().empty(),"handshake absent");
    static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
    Bytes login(144);const std::string name="financial-session";
    std::copy(name.begin(),name.end(),login.begin()+12);login[76]='p';
    const auto catalog=feed(session,{58,login});check(catalog.size()>=2 && catalog[0].wire_type==67,"encrypted login failed");
    Bytes selected;append_le(selected,actor,4);
    check(feed(session,{34,selected}).at(0).wire_type==70,"role selection failed");
    const auto lobby=feed(session,{7,{0,0,0,0}});
    check(std::any_of(lobby.begin(),lobby.end(),[](const Frame& f){return f.wire_type==30;}),"channel entry incomplete");
}
Frame one(RichLobbySession& session,const Frame& request) {
    const auto replies=feed(session,request);
    check(session.state()==LobbyState::authenticated,"business request disconnected encrypted session");
    check(replies.size()==1,"unexpected financial reply count");return replies.front();
}
void expect_error(const Frame& reply,std::uint32_t wire,std::int32_t reason) {
    check(reply.wire_type==0xffffffffU && reply.payload.size()==9 && reply.payload.back()==0,"failure shape");
    check(read_le(View(reply.payload).first(4))==wire && read_le(View(reply.payload).subspan(4,4))==static_cast<std::uint32_t>(reason),"failure context");
}
void run(double ratio) {
    const auto base=std::filesystem::temp_directory_path()/("account-session-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(base);const auto path=base/"isolated.sqlite3";
    Storage storage(path,ClientProfile::richonline);
    const auto actor=storage.dispatch("accounts.create",{{"username","financial-session"},{"password","p"}})
        .at("account").at("role_id").get<std::uint32_t>();
    sqlite3* db=nullptr;const auto filename=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(filename.c_str()),&db)==SQLITE_OK,"fixture open");
    const auto result=sqlite3_exec(db,"UPDATE roles SET gold=200,bank=100,coins=100",nullptr,nullptr,nullptr);
    sqlite3_close(db);check(result==SQLITE_OK,"fixture balances");
    std::string logs;
    ServerLobbyAdapter adapter(storage,fixture(ratio),[&](const std::string& event,const nlohmann::json& data){logs+=event+data.dump();});
    RichLobbySession session(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());
    enter(session,actor);static_cast<void>(session.poll());
    expect_error(one(session,{61,amount(201)}),61,-124);
    const auto deposited=one(session,{61,amount(25)});
    check(deposited.wire_type==101 && deposited.payload==amount(25),"deposit did not recover after rejection");
    expect_error(one(session,{62,amount(126)}),62,-124);
    const auto withdrawn=one(session,{62,amount(5)});
    check(withdrawn.wire_type==102 && withdrawn.payload==amount(5),"withdraw did not recover after rejection");
    expect_error(one(session,exchange(101)),42,-112);
    const auto exchanged=one(session,exchange(3));
    check(exchanged.wire_type==79 && exchanged.payload.size()==24,"exchange failed after rejection");
    check(Bytes(exchanged.payload.begin()+16,exchanged.payload.end())==amount(3*ratio),"fractional exchange delta wrong");
    const auto role=storage.roles_for_username("financial-session").at(0);
    check(role["coins"]==97 && role["gold"]==180+3*ratio && role["bank"]==120,"committed balances differ from client delta");
    expect_error(one(session,{61,amount(4)}),61,-131);
    check(one(session,{62,amount(5)}).wire_type==102,"session closed after repeated business failures");
    check(logs.find("insufficient M points")!=std::string::npos,"precise exchange rejection not logged");
    session.finish();
    Storage reopened(path,ClientProfile::richonline);
    check(reopened.roles_for_username("financial-session").at(0)["coins"]==97,"exchange did not survive SQLite reopen");
}
}
int main() {
    try {run(2.5);run(0.5);std::cout<<"PASS NEW encrypted connections financial flow, rejection recovery, fractional ratios\n";}
    catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
