#include "richonline_mail_service.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <future>
#include <iostream>
#include <memory>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class E,class F>void rejected(F action){try{action();}catch(const E&){return;}throw std::runtime_error("expected rejection missing");}
constexpr RichonlineMailMetadataPolicy metadata{{101,-7,{0xa1,0xa2}},{202,9,{0xb1,0xb2}}};
constexpr RichonlineMailResultPolicy results{0,-112};
RichonlineMailSend46 compose(std::uint32_t token=0){
    RichonlineMailSend46 result;result.original.fill(0xcc);result.recipient={'r','e','c','i','p','i','e','n','t'};
    result.subject={'t','e','s','t'};result.body={'[','<','$','1','$','0','>',']','b','o','d','y'};result.attachment_token=token;
    return result;
}
Frame frame(RichonlineMailSend46 send){
    Bytes data(send.original.begin(),send.original.end());
    const auto put=[&](std::size_t offset,const Bytes& value){std::copy(value.begin(),value.end(),data.begin()+static_cast<std::ptrdiff_t>(offset));data[offset+value.size()]=0;};
    put(48,send.recipient);put(84,send.subject);put(144,send.body);
    for(std::size_t i=0;i<4;++i)data[140+i]=static_cast<std::uint8_t>(send.attachment_token>>(8*i));return {46,std::move(data)};
}
struct Fixture {
    std::filesystem::path path;Storage storage;std::int64_t sender,recipient;
    explicit Fixture(std::filesystem::path file):path(std::move(file)),storage(path){
        sender=storage.dispatch("accounts.create",{{"username","sender"},{"password","isolated"}}).at("account").at("role_id");
        recipient=storage.dispatch("accounts.create",{{"username","recipient"},{"password","isolated"}}).at("account").at("role_id");
    }
    auto database(){sqlite3* value=nullptr;const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&value)==SQLITE_OK,"sqlite open");return std::unique_ptr<sqlite3,decltype(&sqlite3_close)>(value,sqlite3_close);}
    void sql(const std::string& command){auto db=database();check(sqlite3_exec(db.get(),command.c_str(),nullptr,nullptr,nullptr)==SQLITE_OK,"fixture SQL");}
    std::int64_t scalar(const std::string& query){auto db=database();sqlite3_stmt* raw=nullptr;check(sqlite3_prepare_v2(db.get(),query.c_str(),-1,&raw,nullptr)==SQLITE_OK,"scalar prepare");const std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> row(raw,sqlite3_finalize);check(sqlite3_step(row.get())==SQLITE_ROW,"scalar row");return sqlite3_column_int64(row.get(),0);}
};
void normal(const std::filesystem::path& root){
    Fixture f(root/"normal.sqlite3");const auto send=compose();const auto committed=f.storage.send_mail("sender",f.sender,send,1791496800,"normal-1",metadata);
    check(committed.status==RichonlineMailMutation::changed && committed.recipient_username=="recipient" && committed.recipient_role==f.recipient,"recipient resolution");
    const auto box=f.storage.mailbox("recipient",f.recipient);check(box.size()==1 && box.front().opaque_kind==0 && box.front().read_word==0 && box.front().attachment_token==0,"normal persisted");
    check(box.front().sender.opaque_actor_word==101 && box.front().recipient.opaque_actor_short==9,"explicit metadata");
    check(std::string(box.front().sender.name.begin(),box.front().sender.name.begin()+6)=="sender","trusted sender name");
    auto replay=send;replay.original.fill(0x71);check(f.storage.send_mail("sender",f.sender,replay,1791496900,"normal-1",{{9,1,{1,1}},{9,1,{1,1}}}).status==RichonlineMailMutation::duplicate,"uninitialized request ignored for retry");
    replay.body.push_back('x');rejected<StorageError>([&]{f.storage.send_mail("sender",f.sender,replay,1791496900,"normal-1",metadata);});
    check(f.scalar("SELECT count(*) FROM native_mail")==1 && f.scalar("SELECT count(*) FROM audit WHERE source='native-mail'")==2,"no repeat delivery or audit");
    rejected<StorageError>([&]{f.storage.send_mail("recipient",f.sender,send,1791496800,"forged",metadata);});
    auto absent=send;absent.recipient={'a','b','s','e','n','t'};rejected<StorageError>([&]{f.storage.send_mail("sender",f.sender,absent,1791496800,"absent",metadata);});
    f.sql("UPDATE roles SET name='sender' WHERE username='recipient'");auto ambiguous=send;ambiguous.recipient={'s','e','n','d','e','r'};rejected<StorageError>([&]{f.storage.send_mail("sender",f.sender,ambiguous,1791496800,"ambiguous",metadata);});
}
void attachment(const std::filesystem::path& root){
    Fixture f(root/"attachment.sqlite3");constexpr std::uint32_t item=0x4100200d;f.sql("UPDATE roles SET gold=1000,coins=2500;INSERT INTO lobby_inventory VALUES('sender',1090527245,2000000000)");
    const auto before=f.scalar("SELECT CAST(sum(gold+coins) AS INTEGER) FROM roles");const auto send=compose(item);
    const auto delivered=f.storage.send_mail("sender",f.sender,send,1791496800,"gift-1",metadata);
    check(f.scalar("SELECT count(*) FROM lobby_inventory WHERE username='sender'")==0,"sender inventory removed");
    check(f.scalar("SELECT CAST(sum(gold+coins) AS INTEGER) FROM roles")==before,"gift charged twice");
    check(f.storage.claim_mail("recipient",f.recipient,{delivered.record.key,item},1791496801).status==RichonlineMailMutation::changed,"gift claim");
    check(f.scalar("SELECT expires_at FROM lobby_inventory WHERE username='recipient'")==2000000000,"expiry preserved");
    check(f.storage.send_mail("sender",f.sender,send,1791496802,"gift-1",metadata).status==RichonlineMailMutation::duplicate,"gift resend after claim");
    check(f.scalar("SELECT count(*) FROM lobby_inventory")==1,"gift duplicate inventory");
    rejected<StorageError>([&]{f.storage.send_mail("sender",f.sender,send,1791496800,"gift-forged",metadata);});
    f.sql("INSERT INTO lobby_inventory VALUES('sender',1090527245,1700000000)");rejected<StorageError>([&]{f.storage.send_mail("sender",f.sender,send,1791496800,"gift-expired",metadata);});
    f.sql("UPDATE lobby_inventory SET expires_at=0 WHERE username='sender';INSERT INTO lobby_equipment SELECT role_id,2,1090527245 FROM roles WHERE username='sender'");
    rejected<StorageError>([&]{f.storage.send_mail("sender",f.sender,send,1791496800,"gift-equipped",metadata);});
    f.sql("DELETE FROM lobby_equipment;CREATE TRIGGER reject_mail_audit BEFORE INSERT ON audit WHEN NEW.source='native-mail' BEGIN SELECT RAISE(ABORT,'audit failure'); END;");
    rejected<StorageError>([&]{f.storage.send_mail("sender",f.sender,send,1791496800,"gift-rollback",metadata);});
    check(f.scalar("SELECT count(*) FROM lobby_inventory WHERE username='sender'")==1 && f.scalar("SELECT count(*) FROM native_mail")==1 && f.scalar("SELECT count(*) FROM operations WHERE operation_id='gift-rollback'")==0,"transaction rollback");
    f.sql("DROP TRIGGER reject_mail_audit");
    std::vector<std::unique_ptr<Storage>> handles;for(int i=0;i<8;++i)handles.push_back(std::make_unique<Storage>(f.path));
    std::vector<std::future<RichonlineMailMutation>> tasks;for(const auto& handle:handles)tasks.push_back(std::async(std::launch::async,[&,ptr=handle.get()]{return ptr->send_mail("sender",f.sender,send,1791496800,"gift-concurrent",metadata).status;}));
    int changed=0,duplicates=0;for(auto& task:tasks){const auto status=task.get();if(status==RichonlineMailMutation::changed)++changed;else if(status==RichonlineMailMutation::duplicate)++duplicates;}
    check(changed==1 && duplicates==7 && f.scalar("SELECT count(*) FROM native_mail")==2 && f.scalar("SELECT count(*) FROM lobby_inventory WHERE username='sender'")==0,"concurrent gift ownership");
}
void service(const std::filesystem::path& root){
    Fixture f(root/"service.sqlite3");auto send=compose();
    auto reply=richonline_mail_send_request(f.storage,"sender",f.sender,frame(send),1791496800,"service-1",results,metadata);
    check(reply.frames.size()==2 && reply.frames[0].wire_type==0xffffffffU && read_le(View(reply.frames[0].payload).subspan(4,4))==0 && reply.frames[1].wire_type==92 && reply.frames[1].payload==Bytes(4,0),"sender completion order");
    check(reply.recipient && reply.recipient->role_id==f.recipient && reply.recipient->frame.wire_type==88,"recipient routed notification");
    reply=richonline_mail_send_request(f.storage,"sender",f.sender,frame(send),1791496800,"service-1",results,metadata);check(reply.frames.size()==2 && !reply.recipient,"replay notification");
    send.attachment_token=123;reply=richonline_mail_send_request(f.storage,"sender",f.sender,frame(send),1791496800,"service-fail",results,metadata);
    check(reply.frames.size()==1 && !reply.recipient && reply.diagnostic=="mail_attachment_not_owned" && read_le(View(reply.frames[0].payload).subspan(4,4))==static_cast<std::uint32_t>(-112),"safe refusal");
    auto malformed=frame(compose());malformed.payload.resize(347);reply=richonline_mail_send_request(f.storage,"sender",f.sender,malformed,1791496800,"service-malformed",results,metadata);check(reply.frames.size()==1 && !reply.recipient,"malformed does not disconnect");
    check(encode_richonline_mail_sent92(13).payload==Bytes({13,0,0,0}),"92 signed key");rejected<CodecError>([]{encode_richonline_mail_sent92(0x80000000);});
}
}
int main(){try{const auto root=std::filesystem::temp_directory_path()/("richonline-mail-send-"+std::to_string(GetCurrentProcessId()));std::filesystem::create_directories(root);normal(root);attachment(root);service(root);std::filesystem::remove_all(root);std::cout<<"richonline_mail_send_tests PASS\n";return 0;}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
