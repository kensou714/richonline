#include "server_lobby_adapter.hpp"
#include "richonline_game_registry.hpp"
#include <algorithm>
#include <bit>
#include <chrono>
#include <fstream>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
BootstrapBlobs fixture(bool mail=true){
    BootstrapBlobs blobs{};blobs.provenance="Isolated lobby workflow fixture; opaque values have no asserted meanings";
    blobs.game_capacity=8;blobs.player_capacity=100;blobs.room_unknown_prefix=0x12345678;
    blobs.setting_text="14";blobs.stage_progress={1,1,2,0};const auto bits=std::bit_cast<std::uint64_t>(2.5);
    for(std::size_t i=0;i<8;++i)blobs.unknown_completion[20+i]=static_cast<std::uint8_t>(bits>>(8*i));
    for(std::uint32_t i=0;i<3;++i){ChannelCatalogEntry channel{};channel.key=i;channel.name_utf8="channel"+std::to_string(i);
        channel.room_capacity=8;channel.player_capacity=100;channel.max_level=20;channel.max_gold=1000000;blobs.channels.push_back(channel);}
    if(mail)blobs.richonline_mail_policy=RichonlineMailBootstrapPolicy{"Explicit isolated mail compatibility fixture",
        {{0xfedcba98U,-32768,{0xab,0xcd}},{0x12345678U,32767,{0x12,0x34}}}};
    return blobs;
}
std::vector<Frame> decode(const std::vector<Bytes>& packets){std::vector<Frame> frames;for(const auto& bytes:packets)frames.push_back(decode_frame(bytes,{Channel::lobby_s2c,219,ClientVersion::richonline}));return frames;}
std::vector<Frame> feed(RichLobbySession& session,const Frame& request){return decode(session.feed(encode_frame(request,{Channel::lobby_c2s,219,ClientVersion::richonline})));}
Frame scalar(std::uint32_t wire,std::uint32_t value){Bytes bytes;append_le(bytes,value,4);return {wire,std::move(bytes)};}
std::vector<Frame> enter(RichLobbySession& session,std::string_view username,std::uint32_t actor,std::uint32_t channel){
    static_cast<void>(session.start());static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
    Bytes login(144);std::copy(username.begin(),username.end(),login.begin()+12);login[76]='p';static_cast<void>(feed(session,{58,login}));
    static_cast<void>(feed(session,scalar(34,actor)));return feed(session,scalar(7,channel));
}
std::uint32_t create(Storage& storage,const char* name){return storage.dispatch("accounts.create",{{"username",name},{"password","p"}}).at("account").at("role_id").get<std::uint32_t>();}
const Frame& find(const std::vector<Frame>& frames,std::uint32_t wire){const auto it=std::find_if(frames.begin(),frames.end(),[&](const Frame& frame){return frame.wire_type==wire;});
    if(it==frames.end()){std::string detail="expected wire "+std::to_string(wire)+" missing; returned";for(const auto& frame:frames){detail+=" "+std::to_string(frame.wire_type);if(frame.wire_type==0xffffffffU&&frame.payload.size()>=8)detail+="(request="+std::to_string(read_le(View(frame.payload).first(4)))+",status="+std::to_string(std::bit_cast<std::int32_t>(read_le(View(frame.payload).subspan(4,4))))+")";}throw std::runtime_error(detail);}return *it;}
void result(const std::vector<Frame>& frames,std::int32_t code){const auto& frame=find(frames,0xffffffffU);check(frame.payload.size()==9&&read_le(View(frame.payload).first(4))==46&&read_le(View(frame.payload).subspan(4,4))==static_cast<std::uint32_t>(code),"mail result contract");}
void text(Bytes& bytes,std::size_t offset,std::string_view value){const auto encoded=client_text(value);std::copy(encoded.begin(),encoded.end(),bytes.begin()+static_cast<std::ptrdiff_t>(offset));bytes.at(offset+encoded.size())=0;}
Frame mail_request(std::string_view recipient){Bytes bytes(348,0xcc);text(bytes,48,recipient);text(bytes,84,"SUBJECT_PRIVATE");text(bytes,144,"[<$1$1>]BODY_PRIVATE");for(std::size_t i=140;i<144;++i)bytes[i]=0;return {46,std::move(bytes)};}
template<class A>std::string hex(const A& bytes){std::string value;constexpr char digits[]="0123456789abcdef";for(const auto byte:bytes){value.push_back(digits[byte>>4]);value.push_back(digits[byte&15]);}return value;}
void explicit_mail_policy_loading(const std::filesystem::path& root){
    const auto blobs=fixture(false);nlohmann::json config={{"provenance",blobs.provenance},{"game_capacity",8},{"player_capacity",100},{"setting_text","14"},{"stage_progress",{1,1,2,0}},
        {"unknown_channel_record_hex",hex(blobs.unknown_channel_record)},{"unknown_role_record_hex",hex(blobs.unknown_role_record)},
        {"unknown_profile_record_hex",hex(blobs.unknown_profile_record)},{"unknown_login_result_hex",hex(blobs.unknown_login_result)},
        {"unknown_identity_record_hex",hex(blobs.unknown_identity_record)},{"unknown_empty_list_hex",hex(blobs.unknown_empty_list)},
        {"unknown_bank_config_hex",hex(blobs.unknown_bank_config)},{"unknown_completion_hex",hex(blobs.unknown_completion)}};
    const auto path=root/"bootstrap.json";const auto write=[&]{std::ofstream output(path,std::ios::binary|std::ios::trunc);output<<config.dump();check(static_cast<bool>(output),"write policy fixture");};
    write();check(!load_bootstrap_blobs(path).richonline_mail_policy,"missing metadata enabled implicitly");
    config["richonline_mail_policy"]={{"provenance","Explicit isolated compatibility values"},
        {"sender_actor",{{"opaque_word",0xffffffffU},{"opaque_short",-32768},{"opaque_padding_hex","abcd"}}},
        {"recipient_actor",{{"opaque_word",0x12345678U},{"opaque_short",32767},{"opaque_padding_hex","1234"}}}};
    write();const auto loaded=load_bootstrap_blobs(path);check(loaded.richonline_mail_policy.has_value(),"metadata policy absent");
    const auto& metadata=loaded.richonline_mail_policy->metadata;check(metadata.sender.opaque_word==0xffffffffU&&metadata.sender.opaque_short==-32768&&metadata.sender.opaque_padding==std::array<std::uint8_t,2>{0xab,0xcd}&&metadata.recipient.opaque_short==32767,"opaque metadata overwritten or truncated");
    const auto rejected=[&]{write();bool failed=false;try{static_cast<void>(load_bootstrap_blobs(path));}catch(const CodecError&){failed=true;}check(failed,"malformed explicit policy accepted");};
    config["richonline_mail_policy"]["sender_actor"]["opaque_short"]=32768;rejected();
    config["richonline_mail_policy"]["sender_actor"]["opaque_short"]=-32768;config["richonline_mail_policy"]["sender_actor"]["opaque_padding_hex"]="zzzz";rejected();
    config["richonline_mail_policy"]["sender_actor"]["opaque_padding_hex"]="abcd";config["richonline_mail_policy"]["provenance"]="";rejected();
    config.erase("richonline_mail_policy");write();check(!load_bootstrap_blobs(path).richonline_mall_policy,"missing mall policy enabled implicitly");
    config["richonline_mall_policy"]={{"ignored_word0",0xffffffffU},{"ignored_word2",0x12345678U},{"refused",-13},
        {"evidence","Explicit isolated NEW mall compatibility values"},{"inventory_date_version","original_2005"},{"verified_client_compatibility_id",""}};
    write();const auto original=load_bootstrap_blobs(path).richonline_mall_policy;
    check(original&&original->ignored_word0==0xffffffffU&&original->ignored_word2==0x12345678U&&original->refused==-13&&original->date_version==RichonlineInventoryDateVersion::original_2005,"mall values truncated or defaulted");
    auto& mall=config["richonline_mall_policy"];mall["inventory_date_version"]="compat_2021_v1";mall["verified_client_compatibility_id"]=richonline_inventory_compatibility_id;
    write();check(load_bootstrap_blobs(path).richonline_mall_policy->date_version==RichonlineInventoryDateVersion::compat_2021_v1,"explicit compat mode not loaded");
    mall["verified_client_compatibility_id"]="unverified";rejected();mall["verified_client_compatibility_id"]=richonline_inventory_compatibility_id;
    mall["inventory_date_version"]="original_2005";rejected();mall["verified_client_compatibility_id"]="";
    mall["inventory_date_version"]="unknown_epoch";rejected();mall["inventory_date_version"]="original_2005";
    mall["ignored_word0"]=4294967296ULL;rejected();mall["ignored_word0"]=0xffffffffU;mall["ignored_word2"]=0.0;rejected();mall["ignored_word2"]=0x12345678U;
    mall["refused"]=0;rejected();mall["refused"]=-13;mall["evidence"]="";rejected();mall["evidence"]="Explicit isolated NEW mall compatibility values";
    mall.erase("inventory_date_version");rejected();
}
void mail_routes_authenticated_recipients_and_survives_reconnect(const std::filesystem::path& root){
    Storage storage(root/"mail.sqlite3");const auto sender=create(storage,"MailSender"),recipient=create(storage,"MailRecipient"),other=create(storage,"MailOther");
    {ServerLobbyAdapter disabled(storage,fixture(false));RichLobbySession session(ServerLobbyOptions{"127.0.0.1",0}.transport(),disabled.callbacks());enter(session,"MailSender",sender,0);
        result(feed(session,mail_request("MailRecipient")),-112);check(session.state()==LobbyState::authenticated&&storage.mailbox("MailRecipient",recipient).empty(),"missing policy mutates or disconnects");session.finish();}
    std::string logs;ServerLobbyAdapter adapter(storage,fixture(),[&](const std::string& event,const nlohmann::json& data){logs+=event+data.dump();});
    const auto options=ServerLobbyOptions{"127.0.0.1",0}.transport();RichLobbySession a(options,adapter.callbacks()),b(options,adapter.callbacks()),c(options,adapter.callbacks());
    enter(a,"MailSender",sender,0);enter(b,"MailRecipient",recipient,2);enter(c,"MailOther",other,1);a.poll();b.poll();c.poll();
    auto response=feed(a,mail_request("MailRecipient"));result(response,0);check(find(response,92).payload==Bytes({0,0,0,0})&&response.size()==2,"pure text fabricated inventory grant");
    auto received=decode(b.poll());check(received.size()==1&&received[0].wire_type==88&&c.poll().empty()&&a.poll().empty(),"recipient88 routed to wrong live session");
    const auto stored=storage.mailbox("MailRecipient",recipient);check(stored.size()==1&&stored[0].sender.opaque_actor_word==0xfedcba98U&&stored[0].sender.opaque_actor_short==-32768&&stored[0].recipient.opaque_padding==std::array<std::uint8_t,2>{0x12,0x34},"explicit mail metadata not persisted");
    check(storage.mailbox("MailSender",sender).empty(),"mail stored in sender mailbox");
    result(feed(a,{46,{1}}),-112);check(a.state()==LobbyState::authenticated,"malformed mail closed session");
    b.finish();a.poll();c.poll();response=feed(a,mail_request("MailRecipient"));result(response,0);check(c.poll().empty()&&a.poll().empty()&&storage.mailbox("MailRecipient",recipient).size()==2,"offline mail lost or leaked");
    RichLobbySession b2(options,adapter.callbacks());const auto snapshot=enter(b2,"MailRecipient",recipient,2);check(std::count_if(snapshot.begin(),snapshot.end(),[](const Frame& frame){return frame.wire_type==88;})==2,"offline mail missing on channel snapshot");
    result(feed(a,mail_request("MailMissing")),-112);check(a.state()==LobbyState::authenticated&&b2.poll().empty(),"missing recipient failed closed or notified other");
    check(logs.find("SUBJECT_PRIVATE")==std::string::npos&&logs.find("BODY_PRIVATE")==std::string::npos&&logs.find("MailRecipient")==std::string::npos,"mail text or recipient name logged");
    a.finish();b2.finish();c.finish();
    {ServerLobbyAdapter restarted(storage,fixture());RichLobbySession session(options,restarted.callbacks());enter(session,"MailSender",sender,0);result(feed(session,mail_request("MailRecipient")),0);
        check(storage.mailbox("MailRecipient",recipient).size()==3,"server restart reused session operation namespace");session.finish();}
}
void account_preferences_are_persistent_without_invented_ack(const std::filesystem::path& root){
    const auto path=root/"preferences.sqlite3";const auto options=ServerLobbyOptions{"127.0.0.1",0}.transport();std::uint32_t actor=0;
    const auto settings=[](const std::vector<Frame>& frames,std::string_view expected){const auto& frame=find(frames,106);Bytes bytes(expected.begin(),expected.end());bytes.push_back(0);check(frame.payload==bytes,"106 did not select account preferences/default");};
    {Storage storage(path);actor=create(storage,"PreferencesA");const auto other=create(storage,"PreferencesB");std::string logs;
        ServerLobbyAdapter adapter(storage,fixture(false),[&](const std::string& event,const nlohmann::json& data){logs+=event+data.dump();});
        RichLobbySession session(options,adapter.callbacks());static_cast<void>(session.start());static_cast<void>(session.feed(encode_frame({759,{113,0,0,0}},{Channel::lobby_c2s,std::nullopt,ClientVersion::richonline})));
        Bytes login(144);const std::string name="PreferencesA";std::copy(name.begin(),name.end(),login.begin()+12);login[76]='p';find(feed(session,{58,std::move(login)}),67);
        check(feed(session,{105,{'1','2',0}}).empty()&&session.state()==LobbyState::authenticated&&storage.preferences_for_username(name)=="12","authenticated105 before role selection failed or invented ACK");
        find(feed(session,scalar(34,actor)),70);settings(feed(session,scalar(7,0)),"12");
        const std::vector<Bytes> invalid{{},{'1','2'},{'1',0,'2',0},{'-','1',0},{'2','1','4','7','4','8','3','6','4','8',0},Bytes(12,'0')};
        for(const auto& payload:invalid)check(feed(session,{105,payload}).empty()&&session.state()==LobbyState::authenticated&&storage.preferences_for_username(name)=="12","invalid105 mutated preferences, disconnected or invented response");
        check(feed(session,{105,{'1','2',0}}).empty()&&feed(session,{105,{'0',0}}).empty()&&storage.preferences_for_username(name)=="0","zero105 was replaced by default or ACKed");session.finish();
        RichLobbySession second(options,adapter.callbacks());settings(enter(second,"PreferencesB",other,0),"14");check(!storage.preferences_for_username("PreferencesB"),"default106 was persisted without105");second.finish();
        RichLobbySession reconnect(options,adapter.callbacks());settings(enter(reconnect,name,actor,0),"0");reconnect.finish();
        check(logs.find("preference_length_or_terminator_invalid")!=std::string::npos&&logs.find("preference_not_decimal")!=std::string::npos&&logs.find("preference_out_of_range")!=std::string::npos,"105 diagnostics omitted exact invalid reason");
        check(logs.find(name)==std::string::npos&&logs.find("PreferencesB")==std::string::npos,"105 diagnostics leaked account identity");
    }
    {Storage reopened(path);ServerLobbyAdapter adapter(reopened,fixture(false));RichLobbySession session(options,adapter.callbacks());settings(enter(session,"PreferencesA",actor,0),"0");session.finish();}
}
Frame room_create(){Bytes bytes(128);text(bytes,0,"room");text(bytes,76,"stage");bytes[32]=0x40;bytes[36]=2;bytes[40]=1;bytes[72]=1;bytes[120]=88;bytes[124]=1;bytes.insert(bytes.end(),88,0xa5);return {3,std::move(bytes)};}
void terminal_waits_for_full_lobby_send(const std::filesystem::path& root){
    Storage storage(root/"terminal.sqlite3");const auto actor=create(storage,"Terminal");bool ready_to_finish=false;int notifications=0;
    auto registry=std::make_shared<RichonlineGameRegistry>([&](const RichonlineRoomSnapshot& room){
        RichonlineGamePlan plan{room.participants.front().connection,room.owner,{{127,0,0,1},18602,123,{1,2,3,4,5,6,7,8}},
            []{return std::vector<Frame>{};},[](const Envelope299&,View){return std::vector<Frame>{};},[] {}};
        plan.game_finished=[&]{return ready_to_finish;};plan.lobby_sent=[&](const Frame& frame){check(frame.wire_type==58&&frame.payload==Bytes({1,0,0,0}),"terminal observer received wrong frame");++notifications;ready_to_finish=false;};
        plan.terminal_pending=[&]{return ready_to_finish;};return std::vector<RichonlineGamePlan>{std::move(plan)};
    },0,std::chrono::seconds(30));
    ServerLobbyAdapter adapter(storage,fixture(false));adapter.set_game_registry(registry);RichLobbySession session(ServerLobbyOptions{"127.0.0.1",0}.transport(),adapter.callbacks());enter(session,"Terminal",actor,0);
    find(feed(session,room_create()),10);find(feed(session,{5,{}}),22);check(session.poll().empty()&&notifications==0,"terminal started before game completion");
    ready_to_finish=true;const auto packets=session.poll();const auto frames=decode(packets);check(frames.size()==2&&frames[0].wire_type==96&&frames[1].wire_type==58&&notifications==0,"enqueue advanced terminal outbox or finish missing");
    session.sent(packets[0]);check(notifications==0,"ready reset marked terminal delivered");session.sent(packets[1]);check(notifications==1,"successful58 not acknowledged to origin plan");
    session.sent(packets[1]);check(notifications==1,"duplicate transport observer confirmed twice");
    check(session.poll().empty(),"finished room emitted duplicate58");find(feed(session,scalar(10,1)),18);
    find(feed(session,{5,{}}),22);check(session.poll().empty(),"second game inherited completed first game");
    ready_to_finish=true;const auto second=session.poll();check(decode(second).size()==2&&notifications==1,"second terminal enqueue confirmed early");
    auto truncated=second[1];truncated.pop_back();bool refused=false;try{session.sent(truncated);}catch(const CodecError&){refused=true;}
    check(refused&&notifications==1,"partial second58 marked delivered");session.sent(second[0]);session.sent(second[1]);
    check(notifications==2&&session.poll().empty(),"second complete58 failed to retire origin game");session.finish();
}
}
int main(){try{
    const auto root=std::filesystem::temp_directory_path()/("lobby-workflow-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(root);
    explicit_mail_policy_loading(root);mail_routes_authenticated_recipients_and_survives_reconnect(root);account_preferences_are_persistent_without_invented_ack(root);terminal_waits_for_full_lobby_send(root);
    std::cout<<"PASS explicit mail metadata, encrypted recipient routing, persistent105/106 without invented ACK, offline/restart durability and terminal58 whole-send boundary\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
