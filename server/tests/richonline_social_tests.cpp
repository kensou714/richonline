#include "richonline_social.hpp"
#include <sqlite3.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
BootstrapBlobs fixture(){
    BootstrapBlobs blobs{};blobs.provenance="isolated social protocol fixture";blobs.game_capacity=8;blobs.player_capacity=100;
    blobs.room_unknown_prefix=0x12345678;blobs.social_server_id=1;blobs.setting_text="14";blobs.stage_progress={1,1,2,0};
    const auto bits=std::bit_cast<std::uint64_t>(2.5);
    for(std::size_t i=0;i<8;++i)blobs.unknown_completion[20+i]=static_cast<std::uint8_t>(bits>>(8*i));return blobs;
}
std::vector<Frame> decode(const std::vector<Bytes>& packets){std::vector<Frame> out;for(const auto& bytes:packets)out.push_back(decode_frame(bytes,{Channel::lobby_s2c,219,ClientVersion::richonline}));return out;}
std::vector<Frame> feed(RichLobbySession& session,const Frame& frame){return decode(session.feed(encode_frame(frame,{Channel::lobby_c2s,219,ClientVersion::richonline})));}
Frame actor(std::uint32_t wire,std::uint32_t id){Bytes bytes;append_le(bytes,id,4);return {wire,std::move(bytes)};}
Frame invitation(std::uint32_t wire,std::uint32_t id,std::string_view text){auto frame=actor(wire,id);const auto bytes=client_text(text);frame.payload.insert(frame.payload.end(),bytes.begin(),bytes.end());frame.payload.resize(36,0);if(wire==29)append_le(frame.payload,static_cast<std::uint32_t>(bytes.size()+1),4);return frame;}
Frame remove_friend(std::string_view text){auto bytes=client_text(text);bytes.resize(32,0);return {31,std::move(bytes)};}
const Frame& find(const std::vector<Frame>& frames,std::uint32_t wire){const auto it=std::find_if(frames.begin(),frames.end(),[&](const auto& frame){return frame.wire_type==wire;});check(it!=frames.end(),"expected wire missing");return *it;}
const Frame& delivery(const std::vector<RichonlineRoomDispatch>& frames,std::uint64_t recipient,std::uint32_t wire){
    const auto it=std::find_if(frames.begin(),frames.end(),[&](const auto& frame){return frame.recipient==recipient&&frame.frame.wire_type==wire;});
    check(it!=frames.end(),"expected presence recipient missing");return it->frame;
}
void location(const Frame& frame,std::uint32_t channel,std::string_view name){
    auto expected_name=client_text(name);expected_name.resize(32,0);
    check(frame.payload.size()==40&&read_le(View(frame.payload).first(4))==1&&read_le(View(frame.payload).subspan(4,4))==channel,"presence uses fabricated server/channel");
    check(Bytes(frame.payload.begin()+8,frame.payload.end())==expected_name,"presence friend identity changed");
}
std::vector<Frame> enter(RichLobbySession& session,const char* name,std::uint32_t id){
    static_cast<void>(session.start());static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
    Bytes login(144);std::copy_n(name,std::char_traits<char>::length(name),login.begin()+12);login[76]='p';static_cast<void>(feed(session,{58,login}));
    static_cast<void>(feed(session,actor(34,id)));return feed(session,{7,{0,0,0,0}});
}
void failed(RichLobbySession& session,Frame request){const auto response=feed(session,request);check(find(response,0xffffffffU).payload.size()==9,"failure contract");check(session.state()==LobbyState::authenticated,"social rejection disconnected");}
void sql(const std::filesystem::path& path,const char* statement){sqlite3* db=nullptr;const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"sql fixture open");const auto result=sqlite3_exec(db,statement,nullptr,nullptr,nullptr);sqlite3_close(db);check(result==SQLITE_OK,"sql fixture execute");}
}
int main(){try{
    const auto root=std::filesystem::temp_directory_path()/("social-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto path=root/"accounts.sqlite3";Storage storage(path);
    const auto create=[&](const char* name){return storage.dispatch("accounts.create",{{"username",name},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();};
    const auto aid=create("SocialA"),bid=create("SocialB"),cid=create("SocialC");std::string logs;
    ServerLobbyAdapter adapter(storage,fixture(),[&](const std::string& event,const nlohmann::json& data){logs+=event+data.dump();});
    const auto options=ServerLobbyOptions{"127.0.0.1",0}.transport();
    RichLobbySession a(options,adapter.callbacks()),b(options,adapter.callbacks()),c(options,adapter.callbacks());
    const auto initial=enter(a,"SocialA",aid);check(find(initial,69).payload==Bytes({0,0,0,0}),"new friends not empty");
    enter(b,"SocialB",bid);enter(c,"SocialC",cid);a.poll();b.poll();c.poll();
    failed(a,actor(30,bid));failed(a,invitation(28,aid,"self"));failed(a,invitation(28,999,"missing"));
    const auto secret=invitation(28,bid,"SECRETX");check(feed(a,secret).empty(),"invitation invented reply");
    const auto asked=decode(b.poll());check(find(asked,63).payload==invitation(28,aid,"SECRETX").payload,"inviter identity not substituted");check(c.poll().empty(),"invitation leaked");
    failed(c,actor(30,aid));failed(a,secret);
    const auto accepted=feed(b,actor(30,aid));const auto aaccepted=decode(a.poll());
    check(read_le(find(accepted,209).payload)==aid&&read_le(find(aaccepted,209).payload)==bid,"accept actors");
    check(read_le(View(find(accepted,61).payload).first(4))==1,"server id absent");check(c.poll().empty(),"accept leaked");
    failed(b,actor(30,aid));failed(a,secret);
    {RichonlineSocial reopened(storage,fixture(),1);const auto frames=reopened.enter(71,"SocialA",aid,0);check(frames.at(0).frame.wire_type==69&&read_le(View(frames[0].frame.payload).first(4))==1,"friendship not durable");
        check(read_le(View(frames[0].frame.payload).subspan(4,4))==bid&&frames[0].frame.payload.size()==212,"real friend profile record");
        bool rejected=false;try{reopened.enter(72,"SocialC",bid,0);}catch(const StorageError&){rejected=true;}check(rejected,"cross account social ownership");
    }
    {RichonlineSocial channels(storage,fixture(),1);
        channels.enter(81,"SocialA",aid,0);
        const auto admitted=channels.enter(82,"SocialB",bid,1);
        location(delivery(admitted,81,61),1,"SocialB");location(delivery(admitted,82,61),0,"SocialA");
        location(delivery(channels.leave(82),81,62),1,"SocialB");
        const auto moved=channels.enter(83,"SocialB",bid,2);
        location(delivery(moved,81,61),2,"SocialB");location(delivery(moved,83,61),0,"SocialA");
        location(delivery(channels.leave(81),83,62),0,"SocialA");
        const auto reconnected=channels.enter(84,"SocialA",aid,1);
        check(delivery(reconnected,84,69).payload.size()==212,"reconnect lacks durable friend snapshot");
        location(delivery(reconnected,84,61),2,"SocialB");location(delivery(reconnected,83,61),1,"SocialA");
    }
    b.finish();const auto offline=decode(a.poll());check(find(offline,62).payload.size()==40,"offline notification absent");c.poll();
    RichLobbySession b2(options,adapter.callbacks());const auto again=enter(b2,"SocialB",bid);
    check(read_le(View(find(again,69).payload).first(4))==1,"reconnect snapshot absent");
    check(find(again,69).wire_type==69&&find(again,61).wire_type==61,"snapshot precedes online");
    check(find(decode(a.poll()),61).payload.size()==40,"online friend notification absent");c.poll();
    check(find(feed(a,remove_friend("SocialB")),211).payload==remove_friend("SocialB").payload,"delete self ack");
    check(find(decode(b2.poll()),211).payload==remove_friend("SocialA").payload,"mutual delete notification");check(c.poll().empty(),"delete leaked");
    failed(a,remove_friend("SocialB"));
    check(feed(a,invitation(28,bid,"again")).empty(),"second invite");b2.poll();
    sql(path,"CREATE TRIGGER reject_social BEFORE INSERT ON audit WHEN NEW.field='friendship' BEGIN SELECT RAISE(ABORT,'fixture'); END;");
    failed(b2,actor(30,aid));check(a.poll().empty(),"failed commit notified friend");
    {RichonlineSocial reopened(storage,fixture(),1);check(reopened.enter(91,"SocialA",aid,0)[0].frame.payload==Bytes({0,0,0,0}),"audit failure did not rollback friendship");}
    sql(path,"DROP TRIGGER reject_social;");
    check(feed(b2,invitation(29,aid,"no")).empty(),"decline invented ack");check(find(decode(a.poll()),210).payload==invitation(28,bid,"no").payload,"decline sender");
    check(feed(a,invitation(28,bid,"stale")).empty(),"stale setup");b2.poll();a.finish();b2.poll();c.poll();
    RichLobbySession a2(options,adapter.callbacks());enter(a2,"SocialA",aid);b2.poll();c.poll();failed(b2,actor(30,aid));
    for(const auto wire:{28U,29U,30U,31U})failed(a2,{wire,{1}});
    auto malformed=invitation(28,bid,"x");std::fill(malformed.payload.begin()+4,malformed.payload.end(),static_cast<std::uint8_t>('x'));failed(a2,malformed);
    check(logs.find("SECRETX")==std::string::npos,"invitation plaintext logged");
    {RichonlineSocial reopened(storage,fixture(),1);const auto frames=reopened.enter(88,"SocialA",aid,0);check(frames[0].frame.payload==Bytes({0,0,0,0}),"delete not durable");
        reopened.enter(89,"SocialB",bid,1);const auto denied=reopened.receive(88,invitation(28,bid,"cross-channel"));check(!denied.rejection.empty(),"cross channel invite accepted");}
    a2.finish();b2.finish();c.finish();
    std::cout<<"PASS encrypted NEW friend invite/accept/decline/delete, durable SQLite, reconnect presence, session/identity isolation\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
