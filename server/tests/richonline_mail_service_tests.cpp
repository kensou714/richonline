#include "richonline_mail_service.hpp"
#include "lobby.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<std::size_t N>std::array<std::uint8_t,N> field(const std::string& text){std::array<std::uint8_t,N> result;result.fill(0xcc);std::copy(text.begin(),text.end(),result.begin());result.at(text.size())=0;return result;}
RichonlineMailDelivery delivery(){return {{77,{111,field<32>("sender"),3,{0xab,0xcd}},{222,field<32>("recipient"),4,{0x12,0x34}},field<21>("Gift"),field<12>("2026-10-09"),field<11>("12:13:14"),{7,9},2,0x4100100d,field<204>("Message")},13,2000000000,"service-test-mail"};}
std::vector<Frame> feed(RichLobbySession& session,Frame frame){
    const auto bytes=encode_frame(frame,{Channel::lobby_c2s,219,ClientVersion::richonline});std::vector<Frame> replies;
    for(std::size_t at=0;at<bytes.size();){const auto count=std::min<std::size_t>(7,bytes.size()-at);for(const auto& reply:session.feed(View(bytes).subspan(at,count)))replies.push_back(decode_frame(reply,{Channel::lobby_s2c,219,ClientVersion::richonline}));at+=count;}
    check(session.state()==LobbyState::authenticated,"business failure closed encrypted session");return replies;
}
Frame request(std::uint32_t wire,std::initializer_list<std::uint32_t> words){Bytes bytes;for(const auto word:words)append_le(bytes,word,4);return {wire,std::move(bytes)};}
void result(const Frame& frame,std::uint32_t wire,std::int32_t code){check(frame.wire_type==0xffffffffU && frame.payload.size()==9 && frame.payload.back()==0,"generic result shape");check(read_le(View(frame.payload).first(4))==wire && read_le(View(frame.payload).subspan(4,4))==static_cast<std::uint32_t>(code),"generic result selector/code");}
void sql(const std::filesystem::path& path,const char* command){sqlite3* db=nullptr;const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"open fixture");const auto rc=sqlite3_exec(db,command,nullptr,nullptr,nullptr);sqlite3_close(db);check(rc==SQLITE_OK,"fixture SQL");}
void run(){
    const auto root=std::filesystem::temp_directory_path()/("mail-service-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(root);const auto path=root/"isolated.sqlite3";
    Storage storage(path);const auto role=storage.dispatch("accounts.create",{{"username","mail-user"},{"password","p"}}).at("account").at("role_id").get<std::int64_t>();
    const auto mail=delivery();storage.deliver_mail("mail-user",role,mail);std::vector<std::string> diagnostics;
    LobbyCallbacks callbacks;
    callbacks.verify_credentials=[&](const std::string& user,View password){return storage.verify_credentials(user,password);};
    callbacks.login_responses=[&](const LobbyLogin& login){return richonline_mail_snapshot(storage,login.username_utf8,role);};
    callbacks.authenticated_request=[&](const LobbyLogin& login,const Frame& frame){auto reply=richonline_mail_request(storage,login.username_utf8,role,frame,1000,{0,-112});check(reply.has_value(),"service did not handle mail opcode");diagnostics.push_back(reply->diagnostic);return reply->frames;};
    RichLobbySession session({"127.0.0.1",0,local_lobby_handshake(),ClientVersion::richonline},callbacks);
    check(!session.start().empty(),"handshake");session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline}));
    Bytes login(144);const std::string name="mail-user";std::copy(name.begin(),name.end(),login.begin()+12);login[76]='p';
    const auto snapshot=feed(session,{58,login});check(snapshot.size()==1 && snapshot.front().wire_type==88 && snapshot.front().payload==encode_richonline_mail_record88(mail.record).payload,"encrypted mailbox snapshot");
    auto replies=feed(session,request(48,{7,9,123}));check(replies.size()==1,"forged claim response count");result(replies[0],48,-112);
    check(storage.lobby_inventory("mail-user",role,1000).items.empty(),"failed claim changed inventory");
    replies=feed(session,request(49,{7,9}));check(replies.size()==1,"pending attachment delete");result(replies[0],49,-112);
    check(feed(session,request(56,{1,7,9,1})).empty(),"read invented ACK");
    check(feed(session,request(56,{1,7,999,1})).empty(),"missing read invented ACK");
    sql(path,"CREATE TRIGGER fail_mail BEFORE INSERT ON audit WHEN NEW.source='native-mail' BEGIN SELECT RAISE(ABORT,'injected'); END");
    replies=feed(session,request(48,{7,9,mail.record.attachment_token}));check(replies.size()==1,"DB failure response");result(replies[0],48,-112);
    sql(path,"DROP TRIGGER fail_mail");
    replies=feed(session,request(48,{7,9,mail.record.attachment_token}));check(replies.size()==2,"successful claim response count");result(replies[0],48,0);
    check(replies[1].wire_type==93 && replies[1].payload==encode_richonline_mail_claimed93({7,9},13).payload,"claim result must precede real inventory notification");
    replies=feed(session,request(48,{7,9,mail.record.attachment_token}));check(replies.size()==1,"duplicate emitted inventory notification");result(replies[0],48,0);
    check(storage.lobby_inventory("mail-user",role,1000).items==std::vector<std::uint32_t>{13},"single real inventory grant");
    replies=feed(session,request(49,{7,9}));check(replies.size()==2 && replies[1].wire_type==91,"delete notification");result(replies[0],49,0);
    replies=feed(session,request(49,{7,9}));check(replies.size()==1,"duplicate delete notification");result(replies[0],49,0);
    replies=feed(session,request(49,{7,404}));check(replies.size()==1,"missing delete response");result(replies[0],49,-112);
    check(richonline_mail_snapshot(storage,"mail-user",role).empty(),"deleted snapshot");
    check(!richonline_mail_request(storage,"mail-user",role,{46,{}},1000,{0,-112}),"unproven46 handled as success");
    check(std::find(diagnostics.begin(),diagnostics.end(),"token_mismatch")!=diagnostics.end(),"precise denial lost");session.finish();
}
}
int main(){try{run();std::cout<<"PASS encrypted authenticated mail failure recovery, snapshot/read/delete, SQLite rollback and no duplicate93\n";}catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}}
