#include "richonline_mail.hpp"
#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <future>
#include <iostream>
#include <memory>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class E,class F>void rejected(F action){try{action();}catch(const E&){return;}throw std::runtime_error("expected rejection missing");}
template<std::size_t N>std::array<std::uint8_t,N> string_field(const std::string& text){std::array<std::uint8_t,N> value;value.fill(0xcc);check(text.size()<N,"fixture text");std::copy(text.begin(),text.end(),value.begin());value[text.size()]=0;return value;}
RichonlineMailRecord88 record(std::uint32_t low,std::uint32_t token){
    return {0x12345678,{101,string_field<32>("Sender"),-7,{0xa1,0xa2}},
        {202,string_field<32>("Recipient"),9,{0xb1,0xb2}},string_field<21>("subject"),string_field<12>("2026-10-09"),
        string_field<11>("01:02:03"),{17,low},2,token,string_field<204>("body")};
}
void codec(){
    const auto r=record(23,0x4100200d);const auto frame=encode_richonline_mail_record88(r);check(frame.wire_type==88 && frame.payload.size()==348,"record shape");
    const auto decoded=decode_richonline_mail_record88(frame.payload);check(encode_richonline_mail_record88(decoded).payload==frame.payload,"opaque fields not preserved");
    check(decoded.sender.opaque_actor_short==-7 && decoded.recipient.opaque_actor_word==202 && decoded.read_word==2,"record offsets");
    Bytes claim;append_le(claim,17,4);append_le(claim,23,4);append_le(claim,0x4100200d,4);
    const auto c=decode_richonline_mail_claim48(claim);check(c.key==r.key && c.attachment_token==r.attachment_token,"claim offsets");
    check(decode_richonline_mail_delete49(View(claim).first(8))==r.key,"delete offsets");
    Bytes read;for(const auto n:{1U,17U,23U,1U})append_le(read,n,4);check(decode_richonline_mail_read56(read).key==r.key,"read selectors");
    read[0]=2;rejected<CodecError>([&]{decode_richonline_mail_read56(read);});
    const auto deleted=encode_richonline_mail_deleted91(r.key);check(deleted.wire_type==91 && deleted.payload==Bytes(claim.begin(),claim.begin()+8),"delete response");
    const auto granted=encode_richonline_mail_claimed93(r.key,13);check(granted.wire_type==93 && read_le(View(granted.payload).first(4))==13 && granted.payload.size()==12,"grant response");
    auto send=frame.payload;std::fill(send.begin(),send.begin()+48,0xcc);const auto request=decode_richonline_mail_send46(send);
    check(request.recipient==Bytes({'R','e','c','i','p','i','e','n','t'}) && request.attachment_token==r.attachment_token,"send known fields");
    check(std::equal(request.original.begin(),request.original.end(),send.begin()),"send raw unknown preservation");
    validate_richonline_mail_send46(request);
    auto long_request=request;long_request.subject=Bytes(21,'x');rejected<CodecError>([&]{validate_richonline_mail_send46(long_request);});
    long_request=request;long_request.body=Bytes(201,'x');rejected<CodecError>([&]{validate_richonline_mail_send46(long_request);});
    long_request=request;long_request.recipient.clear();rejected<CodecError>([&]{validate_richonline_mail_send46(long_request);});
    long_request=request;long_request.body={0xa4};rejected<CodecError>([&]{validate_richonline_mail_send46(long_request);});
    for(std::size_t size:{0U,8U,12U,347U,349U})rejected<CodecError>([&]{decode_richonline_mail_record88(Bytes(size,0));});
    auto broken=r;broken.body.fill('x');rejected<CodecError>([&]{encode_richonline_mail_record88(broken);});
    broken=r;broken.body=string_field<204>(std::string(201,'x'));rejected<CodecError>([&]{encode_richonline_mail_record88(broken);});
    broken=r;broken.time_text=string_field<11>(std::string(10,'x'));rejected<CodecError>([&]{encode_richonline_mail_record88(broken);});
}
struct Fixture {
    std::filesystem::path path;Storage storage;std::int64_t role,other;
    explicit Fixture(std::filesystem::path p):path(std::move(p)),storage(path){
        role=storage.dispatch("accounts.create",{{"username","recipient"},{"password","isolated"}}).at("account").at("role_id");
        other=storage.dispatch("accounts.create",{{"username","other"},{"password","isolated"}}).at("account").at("role_id");
    }
    void sql(const std::string& command){sqlite3* db=nullptr;const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"sqlite open");const auto rc=sqlite3_exec(db,command.c_str(),nullptr,nullptr,nullptr);sqlite3_close(db);check(rc==SQLITE_OK,"fixture SQL");}
    auto deliver(std::uint32_t key,std::optional<std::uint32_t> item=13,std::int64_t expires=1000){
        RichonlineMailDelivery delivery{record(key,item?0x4100200d:0),item,item?expires:0,"delivery-"+std::to_string(key)};
        check(storage.deliver_mail("recipient",role,delivery)==RichonlineMailMutation::changed,"delivery");return delivery;
    }
};
void storage(const std::filesystem::path& root){
    Fixture f(root/"mail.sqlite3");check(f.storage.mailbox("recipient",f.role).empty(),"empty mailbox");auto d=f.deliver(1);
    check(f.storage.deliver_mail("recipient",f.role,d)==RichonlineMailMutation::duplicate,"delivery replay");
    auto conflicting=d;conflicting.record.read_word=1;rejected<StorageError>([&]{f.storage.deliver_mail("recipient",f.role,conflicting);});
    conflicting=d;conflicting.record.key.low=0x80000000;conflicting.operation_id="bad-client-key";rejected<StorageError>([&]{f.storage.deliver_mail("recipient",f.role,conflicting);});
    rejected<StorageError>([&]{f.storage.mailbox("other",f.role);});
    check(f.storage.mailbox("other",f.other).empty(),"other ownership list");
    const RichonlineMailClaim48 claim{d.record.key,d.record.attachment_token};
    check(f.storage.claim_mail("other",f.other,claim,100).status==RichonlineMailMutation::missing,"other claim");
    check(f.storage.claim_mail("recipient",f.role,{d.record.key,999},100).status==RichonlineMailMutation::token_mismatch,"forged token");
    check(f.storage.delete_mail("recipient",f.role,d.record.key)==RichonlineMailMutation::attachment_pending,"pending attachment deletion");
    check(f.storage.read_mail("recipient",f.role,d.record.key)==RichonlineMailMutation::changed && f.storage.read_mail("recipient",f.role,d.record.key)==RichonlineMailMutation::duplicate,"read idempotency");
    check(f.storage.mailbox("recipient",f.role).front().read_word==1,"read persists");
    check(f.storage.claim_mail("recipient",f.role,claim,100).status==RichonlineMailMutation::changed,"claim");
    check(f.storage.claim_mail("recipient",f.role,claim,100).status==RichonlineMailMutation::duplicate,"duplicate claim");
    check(f.storage.lobby_inventory("recipient",f.role,100).items==std::vector<std::uint32_t>{13},"inventory single grant");
    check(f.storage.mailbox("recipient",f.role).front().attachment_token==0,"mail attachment cleared");
    check(f.storage.deliver_mail("recipient",f.role,d)==RichonlineMailMutation::duplicate,"replay after read/claim");
    check(f.storage.delete_mail("recipient",f.role,d.record.key)==RichonlineMailMutation::changed && f.storage.delete_mail("recipient",f.role,d.record.key)==RichonlineMailMutation::duplicate,"delete replay");
    check(f.storage.mailbox("recipient",f.role).empty(),"deleted removed from mailbox");
    auto second=f.deliver(2);check(f.storage.claim_mail("recipient",f.role,{second.record.key,second.record.attachment_token},100).status==RichonlineMailMutation::inventory_conflict,"unique key conflict preserves attachment");
    auto expired=f.deliver(3,14,50);check(f.storage.claim_mail("recipient",f.role,{expired.record.key,expired.record.attachment_token},100).status==RichonlineMailMutation::attachment_expired,"expired attachment");
    auto plain=f.deliver(4,{});check(f.storage.claim_mail("recipient",f.role,{plain.record.key,0},100).status==RichonlineMailMutation::no_attachment,"text mail has no reward");
    check(f.storage.delete_mail("recipient",f.role,plain.record.key)==RichonlineMailMutation::changed,"text mail deletion");
    Storage reopen(f.path);check(reopen.mailbox("recipient",f.role).size()==2,"restart state");
    Storage original(root/"old.sqlite3",ClientProfile::original);rejected<StorageError>([&]{original.mailbox("recipient",1);});
}
void rollback_and_concurrency(const std::filesystem::path& root){
    Fixture f(root/"rollback.sqlite3");auto d=f.deliver(1);const RichonlineMailClaim48 claim{d.record.key,d.record.attachment_token};
    f.sql("CREATE TRIGGER deny_mail BEFORE INSERT ON audit WHEN NEW.source='native-mail' BEGIN SELECT RAISE(ABORT,'injected'); END");
    rejected<StorageError>([&]{f.storage.claim_mail("recipient",f.role,claim,100);});
    check(f.storage.lobby_inventory("recipient",f.role,100).items.empty() && f.storage.mailbox("recipient",f.role).front().attachment_token==d.record.attachment_token,"claim rollback");
    rejected<StorageError>([&]{f.storage.read_mail("recipient",f.role,d.record.key);});check(f.storage.mailbox("recipient",f.role).front().read_word==2,"read rollback");
    const RichonlineMailDelivery failed_delivery{record(2,0),{},0,"failed-delivery"};
    rejected<StorageError>([&]{f.storage.deliver_mail("recipient",f.role,failed_delivery);});check(f.storage.mailbox("recipient",f.role).size()==1,"delivery rollback");
    f.sql("DROP TRIGGER deny_mail");std::vector<std::unique_ptr<Storage>> handles;std::vector<std::future<RichonlineMailClaimResult>> replies;
    for(int i=0;i<8;++i)handles.push_back(std::make_unique<Storage>(f.path));
    for(auto& handle:handles)replies.push_back(std::async(std::launch::async,[&,db=handle.get()]{return db->claim_mail("recipient",f.role,claim,100);}));
    int changed=0,duplicates=0;for(auto& reply:replies){const auto result=reply.get();changed+=result.status==RichonlineMailMutation::changed;duplicates+=result.status==RichonlineMailMutation::duplicate;}
    check(changed==1 && duplicates==7 && f.storage.lobby_inventory("recipient",f.role,100).items.size()==1,"concurrent duplicate grant");
    f.sql("CREATE TRIGGER deny_delete BEFORE INSERT ON audit WHEN NEW.source='native-mail' BEGIN SELECT RAISE(ABORT,'injected'); END");
    rejected<StorageError>([&]{f.storage.delete_mail("recipient",f.role,d.record.key);});check(f.storage.mailbox("recipient",f.role).size()==1,"delete rollback");
}
}
int main(){try{const auto root=std::filesystem::temp_directory_path()/("mail-native-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(root);
    codec();storage(root);rollback_and_concurrency(root);std::cout<<"PASS NEW mail codecs, opaque preservation, ownership, SQLite read/delete/claim, replay, rollback and concurrent grants\n";
}catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}}
