#include "server_lobby_adapter.hpp"
#include "richonline_game_registry.hpp"
#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
Frame words(std::uint32_t wire,std::initializer_list<std::uint32_t> values){Bytes p;for(auto v:values)append_le(p,v,4);return {wire,std::move(p)};}
std::vector<Frame> decode(const std::vector<Bytes>& packets){std::vector<Frame> out;for(const auto& p:packets)out.push_back(decode_frame(p,{Channel::lobby_s2c,219,ClientVersion::richonline}));return out;}
std::vector<Frame> send(RichLobbySession& s,const Frame& f){return decode(s.feed(encode_frame(f,{Channel::lobby_c2s,219,ClientVersion::richonline})));}
const Frame& find(const std::vector<Frame>& frames,std::uint32_t wire){const auto it=std::find_if(frames.begin(),frames.end(),[&](const auto& f){return f.wire_type==wire;});if(it==frames.end())throw std::runtime_error("missing wire "+std::to_string(wire));return *it;}
std::uint32_t field(const Frame& f,std::size_t offset){return read_le(View(f.payload).subspan(offset,4));}
void rejected(RichLobbySession& s,const Frame& request){const auto frames=send(s,request);const auto& f=find(frames,0xffffffffU);check(field(f,0)==request.wire_type&&field(f,4)==0xffffffffU&&s.state()==LobbyState::authenticated,"refusal lost request ID or authentication");}
BootstrapBlobs fixture(){BootstrapBlobs b{};b.provenance="Explicit isolated NEW lobby membership fixture";b.game_capacity=8;b.player_capacity=100;b.room_unknown_prefix=0x12345678;b.setting_text="14";b.stage_progress={1,1,2,0};b.social_server_id=1;
 const auto bits=std::bit_cast<std::uint64_t>(2.5);for(std::size_t i=0;i<8;++i)b.unknown_completion[20+i]=static_cast<std::uint8_t>(bits>>(8*i));
 for(std::uint32_t i=0;i<2;++i){ChannelCatalogEntry c{};c.key=i;c.name_utf8="channel";c.room_capacity=8;c.player_capacity=100;c.max_level=20;c.max_gold=1000000;b.channels.push_back(c);}return b;}
std::vector<Frame> enter(RichLobbySession& s,std::string_view name,std::uint32_t actor,std::uint32_t channel){s.start();s.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline}));Bytes p(144);std::copy(name.begin(),name.end(),p.begin()+12);p[76]='p';send(s,{58,p});send(s,words(34,{actor}));return send(s,words(7,{channel}));}
Frame create_room(){Bytes p(128);p[0]='r';p[76]='s';p[40]=4;p[72]=4;p[124]=1;p[32]=0x40;p[120]=88;p.insert(p.end(),88,0xa5);return {3,p};}
Frame kick(std::uint32_t actor,std::uint32_t room){auto f=words(27,{actor,room,actor});f.payload.resize(44,0xcc);f.payload[12]=1;f.payload[13]=1;f.payload[14]=0;return f;}
void lifecycle(const std::filesystem::path& root){Storage db(root/"membership.sqlite3");const auto account=[&](const char* name){return db.dispatch("accounts.create",{{"username",name},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();};
 const auto aid=account("MemberA"),bid=account("MemberB"),cid=account("MemberC"),did=account("MemberD");
 ServerLobbyAdapter adapter(db,fixture());const auto options=ServerLobbyOptions{"127.0.0.1",0}.transport();RichLobbySession a(options,adapter.callbacks()),b(options,adapter.callbacks()),c(options,adapter.callbacks()),d(options,adapter.callbacks());
 enter(a,"MemberA",aid,0);enter(b,"MemberB",bid,0);enter(c,"MemberC",cid,1);a.poll();b.poll();c.poll();
 auto invitation=words(28,{bid});invitation.payload.resize(36,0);send(a,invitation);find(decode(b.poll()),63);find(send(b,words(30,{aid})),209);a.poll();
 const auto created=send(a,create_room());const auto room=field(find(created,10),0);b.poll();
 find(send(b,words(4,{room,0,1})),12);a.poll();
 const auto team=send(b,words(9,{3}));check(field(find(team,17),0)==bid&&field(find(team,17),4)==3,"team ack fields");check(field(find(decode(a.poll()),17),0)==bid&&c.poll().empty(),"team observer routing");
 const auto late=enter(d,"MemberD",did,0);bool profile=false,joined=false;for(const auto& f:late){if(f.wire_type==7&&field(f,0)==bid)profile=field(f,44)==3;if(f.wire_type==12&&field(f,0)==bid)joined=field(f,8)==3;}check(profile&&joined,"late team cache reverted to seat");a.poll();b.poll();
 rejected(b,words(9,{4}));rejected(b,kick(aid,room));rejected(a,kick(aid,room));rejected(a,kick(cid,room));rejected(a,kick(bid,room+1));auto forged=kick(bid,room);forged.payload[8]^=1;rejected(a,forged);
 send(b,{5,{}});a.poll();d.poll();rejected(b,words(9,{1}));send(b,{60,{}});a.poll();d.poll();
 const auto kicked=send(a,kick(bid,room));const auto& response=find(kicked,27);auto expected=words(27,{aid,aid,room,bid});expected.payload.insert(expected.payload.end(),{1,1,0});check(response.payload==expected.payload,"kick identities or reason incorrect");
 find(decode(b.poll()),27);find(decode(d.poll()),27);check(c.poll().empty(),"kick crossed channel");rejected(a,kick(bid,room));rejected(b,words(9,{1}));find(send(b,words(4,{room,0,1})),12);a.poll();d.poll();
 rejected(a,words(8,{1}));const auto left=send(a,words(8,{0}));check(left.size()==1&&left[0].wire_type==16&&left[0].payload.empty()&&a.state()==LobbyState::authenticated&&adapter.channel_player_count(0)==2,"channel leave closed account or count stale");
 const auto observed=decode(b.poll());const auto& departure=find(observed,14);check(field(departure,0)==aid&&field(departure,8)==bid,"room owner not transferred");find(observed,55);find(observed,62);d.poll();check(c.poll().empty(),"departure crossed channel");rejected(a,words(8,{0}));
 find(send(a,words(7,{1})),7);check(adapter.channel_player_count(1)==2,"channel reselection needs relogin");c.poll();check(send(a,words(8,{0})).front().wire_type==16,"second channel exit failed");c.poll();
 const auto back=send(a,words(7,{0}));find(back,5);a.poll();b.poll();d.poll();find(send(a,words(4,{room,0,1})),12);b.poll();d.poll();
 a.finish();b.poll();d.poll();b.finish();d.poll();c.finish();d.finish();check(adapter.channel_player_count(0)==0&&adapter.channel_player_count(1)==0,"disconnect left presence");
}
void pending_game_boundary(const std::filesystem::path& root){Storage db(root/"pending.sqlite3");const auto aid=db.dispatch("accounts.create",{{"username","PendingA"},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();const auto bid=db.dispatch("accounts.create",{{"username","PendingB"},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();bool captured=false;
 auto registry=std::make_shared<RichonlineGameRegistry>([&](const RichonlineRoomSnapshot& room){check(room.participants.size()==2&&room.participants[0].slot!=room.participants[1].slot&&room.participants[0].team==0&&room.participants[1].team==0,"teams mistaken for unique simulation slots");captured=true;std::vector<RichonlineGamePlan> plans;for(const auto& peer:room.participants)plans.push_back({peer.connection,peer.actor,{{127,0,0,1},18602,123,{1,2,3,4,5,6,7,8}},[]{return std::vector<Frame>{};},[](const Envelope299&,View){return std::vector<Frame>{};},[]{}});return plans;},0,std::chrono::seconds(30));
 ServerLobbyAdapter adapter(db,fixture());adapter.set_game_registry(registry);const auto options=ServerLobbyOptions{"127.0.0.1",0}.transport();RichLobbySession a(options,adapter.callbacks()),b(options,adapter.callbacks());enter(a,"PendingA",aid,0);enter(b,"PendingB",bid,0);a.poll();const auto room=field(find(send(a,create_room()),10),0);b.poll();send(b,words(4,{room,0,1}));a.poll();send(a,{5,{}});b.poll();find(send(b,{5,{}}),22);check(captured,"registry never received room");a.poll();rejected(a,kick(bid,room));rejected(a,words(9,{2}));rejected(a,words(8,{0}));check(registry->has_room(0,room)&&adapter.channel_player_count(0)==2,"invalid membership mutation cancelled game");a.finish();b.finish();
}
}
int main(){try{const auto root=std::filesystem::temp_directory_path()/("membership-session-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(root);lifecycle(root);pending_game_boundary(root);std::cout<<"PASS encrypted NEW8/9/27 lifecycle, seat/team separation, authorization, late caches and game boundary\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
