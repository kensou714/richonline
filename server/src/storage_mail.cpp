#include "storage_detail.hpp"
#include <limits>
#include <algorithm>
#include <ctime>
#include <windows.h>

namespace richnet {
using namespace storage_detail;
namespace {
void context(ClientProfile profile,sqlite3* db,const std::string& username,std::int64_t role){
    if(profile!=ClientProfile::richonline)throw StorageError("mail_profile_invalid");
    Statement owner(db,"SELECT 1 FROM roles WHERE username=? AND role_id=?");owner.bind(1,username);owner.bind(2,role);
    if(!owner.row())throw StorageError("mail_role_not_owned");
}
void schema(sqlite3* db){execute(db,R"sql(
CREATE TABLE IF NOT EXISTS native_mail(
 role_id INTEGER NOT NULL REFERENCES roles(role_id),key_high INTEGER NOT NULL CHECK(key_high BETWEEN 0 AND 4294967295),
 key_low INTEGER NOT NULL CHECK(key_low BETWEEN 0 AND 4294967295),record_hex TEXT NOT NULL,original_hex TEXT NOT NULL,
 original_token INTEGER NOT NULL CHECK(original_token BETWEEN 0 AND 4294967295),granted_item INTEGER,
 attachment_expires_at INTEGER NOT NULL CHECK(attachment_expires_at>=0),claimed INTEGER NOT NULL CHECK(claimed IN(0,1)),
 deleted INTEGER NOT NULL CHECK(deleted IN(0,1)),operation_id TEXT NOT NULL UNIQUE,
 PRIMARY KEY(role_id,key_high,key_low),CHECK(granted_item IS NULL OR granted_item BETWEEN 1 AND 4294967295)) STRICT;
)sql");}
nlohmann::json delivery_replay_item(sqlite3* db,const std::string& username,const RichonlineMailDelivery& delivery){
    const auto original=delivery.granted_item?nlohmann::json(*delivery.granted_item):nlohmann::json(nullptr);
    Statement mode(db,"SELECT value FROM metadata WHERE key='inventory_date_version'");
    if(!mode.row()||mode.text(0)!=richonline_inventory_compatibility_id)return original;
    Statement exists(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='inventory_date_mail_receipts'");
    if(!exists.row())return original;
    Statement receipt(db,"SELECT original_key FROM inventory_date_mail_receipts WHERE operation_id=? AND username=?");
    receipt.bind(1,delivery.operation_id);receipt.bind(2,username);
    if(!receipt.row())return original;
    const auto old=receipt.record().at("original_key");
    if(old!=original)throw StorageError("mail_delivery_operation_conflict");
    const auto key=old.get<std::uint32_t>();
    // Named certificate13 is an intentionally undated test entitlement.
    if(key==13)return original;
    Statement alias(db,"SELECT new_key FROM inventory_key_aliases WHERE username=? AND old_key=? AND old_version=2005 AND new_version=2021");
    alias.bind(1,username);alias.bind(2,key);
    if(!alias.row())throw StorageError("mail_delivery_migration_alias_missing");
    const auto raw=alias.integer(0);
    if(raw<=0||raw>std::numeric_limits<std::uint32_t>::max())throw StorageError("mail_delivery_migration_alias_invalid");
    const auto current=static_cast<std::uint32_t>(raw);
    if(current!=richonline_inventory_key_from_expiry(key,delivery.attachment_expires_at,RichonlineInventoryDateVersion::compat_2021_v1))
        throw StorageError("mail_delivery_migration_alias_invalid");
    return current;
}
std::string hex(View data){constexpr char digits[]="0123456789abcdef";std::string result;result.reserve(data.size()*2);for(const auto byte:data){result.push_back(digits[byte>>4]);result.push_back(digits[byte&15]);}return result;}
Bytes unhex(const std::string& text){if(text.size()!=696)throw StorageError("mail_record_corrupt");Bytes result;result.reserve(348);
    const auto digit=[](char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw StorageError("mail_record_corrupt");};
    for(std::size_t i=0;i<text.size();i+=2)result.push_back(static_cast<std::uint8_t>(digit(text[i])*16+digit(text[i+1])));return result;}
void bind_key(Statement& row,std::int64_t role,RichonlineMailKey key){row.bind(1,role);row.bind(2,key.high);row.bind(3,key.low);}
void audit(sqlite3* db,const std::string& username,std::int64_t role,RichonlineMailKey key,const std::string& action,const std::string& old_value,const std::string& new_value,const std::string& operation={}){
    Statement row(db,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,'native-mail',?,?)");
    row.bind(1,role);row.bind(2,username);row.bind(3,"mail."+std::to_string(key.high)+"."+std::to_string(key.low));row.bind(4,old_value);row.bind(5,new_value);row.bind(6,action);row.bind(7,operation);row.row();
}
std::string convert_text(const std::string& input,unsigned from,unsigned to){
    if(input.empty())return {};
    if(input.size()>204 || input.find('\0')!=std::string::npos)throw StorageError("mail_name_encoding_invalid");
    const auto count=MultiByteToWideChar(from,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),nullptr,0);
    if(count<=0)throw StorageError("mail_name_encoding_invalid");
    std::wstring wide(static_cast<std::size_t>(count),L'\0');
    if(MultiByteToWideChar(from,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),wide.data(),count)!=count)throw StorageError("mail_name_encoding_invalid");
    BOOL substituted=FALSE;const DWORD flags=to==CP_UTF8?WC_ERR_INVALID_CHARS:WC_NO_BEST_FIT_CHARS;
    auto* used=to==CP_UTF8?nullptr:&substituted;
    const auto size=WideCharToMultiByte(to,flags,wide.data(),count,nullptr,0,nullptr,used);
    if(size<=0 || substituted)throw StorageError("mail_name_encoding_invalid");
    std::string output(static_cast<std::size_t>(size),'\0');
    if(WideCharToMultiByte(to,flags,wide.data(),count,output.data(),size,nullptr,used)!=size || substituted)throw StorageError("mail_name_encoding_invalid");
    return output;
}
template<std::size_t N>std::array<std::uint8_t,N> terminated(View text){
    if(text.size()>=N)throw StorageError("mail_text_capacity");
    // Canonical unused bytes after NUL: NEW's strcpy/stream paths do not read them.
    std::array<std::uint8_t,N> result{};std::copy(text.begin(),text.end(),result.begin());return result;
}
template<std::size_t N>std::array<std::uint8_t,N> terminated(const std::string& text){return terminated<N>(View(reinterpret_cast<const std::uint8_t*>(text.data()),text.size()));}
RichonlineMailActor mail_actor(const std::string& utf8,RichonlineMailActorCompatibility metadata){
    const auto encoded=convert_text(utf8,CP_UTF8,950);if(encoded.empty())throw StorageError("mail_name_empty");
    return {metadata.opaque_word,terminated<32>(encoded),metadata.opaque_short,metadata.opaque_padding};
}
}
RichonlineMailSendResult Storage::send_mail(const std::string& username,std::int64_t role,const RichonlineMailSend46& request,
    std::int64_t now,const std::string& operation,RichonlineMailMetadataPolicy metadata){
    validate_richonline_mail_send46(request);
    if(now<0 || now>253402300799LL || operation.empty() || operation.size()>256 || operation.find('\0')!=std::string::npos || request.attachment_token>0x7fffffffU)
        throw StorageError("mail_send_argument_invalid");
    const auto recipient_name=convert_text(std::string(request.recipient.begin(),request.recipient.end()),950,CP_UTF8);
    const auto canonical=nlohmann::json{{"sender_username",username},{"sender_role",role},{"recipient_cp950",hex(request.recipient)},
        {"subject_cp950",hex(request.subject)},{"body_cp950",hex(request.body)},{"attachment",request.attachment_token}}.dump();
    const std::lock_guard lock(mutex_);Transaction transaction(db_);context(profile_,db_,username,role);schema(db_);
    Statement prior(db_,"SELECT role_id,source,request,result FROM operations WHERE operation_id=?");prior.bind(1,operation);
    if(prior.row()){
        if(prior.integer(0)!=role || prior.text(1)!="native-mail-send" || prior.text(2)!=canonical)throw StorageError("mail_send_operation_conflict");
        const auto result=nlohmann::json::parse(prior.text(3));
        RichonlineMailSendResult replay{RichonlineMailMutation::duplicate,result.at("username").get<std::string>(),result.at("role_id").get<std::int64_t>(),decode_richonline_mail_record88(unhex(result.at("record").get<std::string>()))};
        transaction.commit();return replay;
    }
    Statement sender(db_,"SELECT name FROM roles WHERE username=? AND role_id=?");sender.bind(1,username);sender.bind(2,role);if(!sender.row())throw StorageError("mail_role_not_owned");
    const auto sender_name=sender.text(0);
    Statement recipient(db_,"SELECT role_id,username,name FROM roles WHERE name=? COLLATE BINARY LIMIT 2");recipient.bind(1,recipient_name);
    if(!recipient.row())throw StorageError("mail_recipient_missing");
    const auto recipient_role=recipient.integer(0);const auto recipient_username=recipient.text(1);const auto trusted_recipient_name=recipient.text(2);
    if(recipient.row())throw StorageError("mail_recipient_ambiguous");
    std::int64_t expires=0,inventory_id=0;
    if(request.attachment_token!=0){
        Statement owned(db_,"SELECT expires_at,inventory_id FROM lobby_inventory WHERE username=? AND encoded_item=? AND (expires_at=0 OR expires_at>?) ORDER BY inventory_id LIMIT 1");owned.bind(1,username);owned.bind(2,request.attachment_token);owned.bind(3,now);
        if(!owned.row())throw StorageError("mail_attachment_not_owned");expires=owned.integer(0);
        inventory_id=owned.integer(1);
        if(expires!=0 && expires<=now)throw StorageError("mail_attachment_expired");
        Statement equipped(db_,"SELECT 1 FROM lobby_equipment e JOIN roles r ON r.role_id=e.role_id WHERE r.username=? AND e.encoded_item=? LIMIT 1");equipped.bind(1,username);equipped.bind(2,request.attachment_token);
        if(equipped.row())throw StorageError("mail_attachment_equipped");
    }
    execute(db_,"CREATE TABLE IF NOT EXISTS native_mail_sequence(id INTEGER PRIMARY KEY AUTOINCREMENT) STRICT;");
    RichonlineMailKey key;
    // Administrative deliveries may predate this generator. Skip every key
    // already present (including deleted mail) rather than reusing its identity.
    for(;;){
        execute(db_,"INSERT INTO native_mail_sequence DEFAULT VALUES;");
        const auto sequence=sqlite3_last_insert_rowid(db_);if(sequence<=0)throw StorageError("mail_key_exhausted");
        const auto unsigned_sequence=static_cast<std::uint64_t>(sequence);
        key={static_cast<std::uint32_t>(unsigned_sequence>>31),static_cast<std::uint32_t>(unsigned_sequence&0x7fffffffU)};
        Statement collision(db_,"SELECT 1 FROM native_mail WHERE key_high=? AND key_low=? LIMIT 1");collision.bind(1,key.high);collision.bind(2,key.low);
        if(!collision.row())break;
    }
    // UTC display text is server policy, not a reconstructed original timezone.
    const __time64_t clock_value=now;std::tm utc{};
    if(_gmtime64_s(&utc,&clock_value)!=0)throw StorageError("mail_time_invalid");
    std::array<char,12> date{};std::array<char,11> time{};
    if(std::strftime(date.data(),date.size(),"%Y-%m-%d",&utc)==0 || std::strftime(time.data(),time.size(),"%H:%M:%S",&utc)==0)throw StorageError("mail_time_invalid");
    // 759E80 explicitly renders user sender/subject for kind 0. Read equality 1
    // in 6AEBE0 makes 0 the deliberately chosen unread state.
    RichonlineMailRecord88 record{0,mail_actor(sender_name,metadata.sender),mail_actor(trusted_recipient_name,metadata.recipient),
        terminated<21>(request.subject),terminated<12>(std::string(date.data())),terminated<11>(std::string(time.data())),key,0,request.attachment_token,terminated<204>(request.body)};
    const auto data=hex(encode_richonline_mail_record88(record).payload);
    Statement insert(db_,"INSERT INTO native_mail(role_id,key_high,key_low,record_hex,original_hex,original_token,granted_item,attachment_expires_at,claimed,deleted,operation_id) VALUES(?,?,?,?,?,?,?,?,0,0,?)");
    bind_key(insert,recipient_role,key);insert.bind(4,data);insert.bind(5,data);insert.bind(6,request.attachment_token);
    insert.bind(7,request.attachment_token==0?nlohmann::json(nullptr):nlohmann::json(request.attachment_token));insert.bind(8,expires);insert.bind(9,operation);insert.row();
    if(request.attachment_token!=0){
        Statement remove(db_,"DELETE FROM lobby_inventory WHERE username=? AND inventory_id=?");remove.bind(1,username);remove.bind(2,inventory_id);remove.row();
        if(sqlite3_changes(db_)!=1)throw StorageError("mail_attachment_transfer_conflict");
    }
    audit(db_,username,role,key,"send mail",std::to_string(request.attachment_token),"mail escrow",operation);
    audit(db_,recipient_username,recipient_role,key,"receive mail","absent",data,operation);
    const auto result=nlohmann::json{{"username",recipient_username},{"role_id",recipient_role},{"record",data}}.dump();
    Statement saved(db_,"INSERT INTO operations(operation_id,role_id,source,reason,request,result) VALUES(?,?,'native-mail-send','send mail',?,?)");
    saved.bind(1,operation);saved.bind(2,role);saved.bind(3,canonical);saved.bind(4,result);saved.row();
    RichonlineMailSendResult response{RichonlineMailMutation::changed,recipient_username,recipient_role,std::move(record)};
    transaction.commit();return response;
}
RichonlineMailMutation Storage::deliver_mail(const std::string& username,std::int64_t role,const RichonlineMailDelivery& delivery){
    const auto encoded=encode_richonline_mail_record88(delivery.record).payload;
    if(delivery.operation_id.empty() || delivery.operation_id.size()>256 || delivery.operation_id.find('\0')!=std::string::npos ||
       delivery.record.key.low>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
       delivery.attachment_expires_at<0 || (delivery.granted_item && (*delivery.granted_item==0 || delivery.record.attachment_token==0)) ||
       (!delivery.granted_item && delivery.attachment_expires_at!=0))throw StorageError("mail_delivery_invalid");
    const std::lock_guard lock(mutex_);Transaction transaction(db_);context(profile_,db_,username,role);schema(db_);
    const auto data=hex(encoded);Statement prior(db_,"SELECT role_id,key_high,key_low,original_hex,original_token,granted_item,attachment_expires_at FROM native_mail WHERE operation_id=?");prior.bind(1,delivery.operation_id);
    if(prior.row()){
        const auto old=prior.record();const auto item=delivery_replay_item(db_,username,delivery);
        if(prior.integer(0)!=role || old.at("key_high")!=delivery.record.key.high || old.at("key_low")!=delivery.record.key.low ||
           old.at("original_hex")!=data || old.at("original_token")!=delivery.record.attachment_token ||
           old.at("granted_item")!=item || old.at("attachment_expires_at")!=delivery.attachment_expires_at)throw StorageError("mail_delivery_operation_conflict");
        transaction.commit();return RichonlineMailMutation::duplicate;
    }
    Statement row(db_,"INSERT INTO native_mail(role_id,key_high,key_low,record_hex,original_token,granted_item,attachment_expires_at,claimed,deleted,operation_id,original_hex) VALUES(?,?,?,?,?,?,?,0,0,?,?)");
    bind_key(row,role,delivery.record.key);row.bind(4,data);row.bind(5,delivery.record.attachment_token);row.bind(6,delivery.granted_item?nlohmann::json(*delivery.granted_item):nlohmann::json(nullptr));row.bind(7,delivery.attachment_expires_at);row.bind(8,delivery.operation_id);row.bind(9,data);row.row();
    audit(db_,username,role,delivery.record.key,"delivery","absent",data);transaction.commit();return RichonlineMailMutation::changed;
}
std::vector<RichonlineMailRecord88> Storage::mailbox(const std::string& username,std::int64_t role){
    const std::lock_guard lock(mutex_);Transaction transaction(db_);context(profile_,db_,username,role);schema(db_);
    Statement rows(db_,"SELECT record_hex FROM native_mail WHERE role_id=? AND deleted=0 ORDER BY key_high,key_low");rows.bind(1,role);std::vector<RichonlineMailRecord88> result;
    while(rows.row())result.push_back(decode_richonline_mail_record88(unhex(rows.text(0))));transaction.commit();return result;
}
RichonlineMailMutation Storage::read_mail(const std::string& username,std::int64_t role,RichonlineMailKey key){
    const std::lock_guard lock(mutex_);Transaction transaction(db_);context(profile_,db_,username,role);schema(db_);
    Statement row(db_,"SELECT record_hex FROM native_mail WHERE role_id=? AND key_high=? AND key_low=? AND deleted=0");bind_key(row,role,key);
    if(!row.row())return RichonlineMailMutation::missing;auto record=decode_richonline_mail_record88(unhex(row.text(0)));
    if(record.read_word==1){transaction.commit();return RichonlineMailMutation::duplicate;}const auto previous=record.read_word;record.read_word=1;
    Statement update(db_,"UPDATE native_mail SET record_hex=? WHERE role_id=? AND key_high=? AND key_low=?");update.bind(1,hex(encode_richonline_mail_record88(record).payload));update.bind(2,role);update.bind(3,key.high);update.bind(4,key.low);update.row();
    audit(db_,username,role,key,"mark read",std::to_string(previous),"1");transaction.commit();return RichonlineMailMutation::changed;
}
RichonlineMailMutation Storage::delete_mail(const std::string& username,std::int64_t role,RichonlineMailKey key){
    const std::lock_guard lock(mutex_);Transaction transaction(db_);context(profile_,db_,username,role);schema(db_);
    Statement row(db_,"SELECT original_token,claimed,deleted FROM native_mail WHERE role_id=? AND key_high=? AND key_low=?");bind_key(row,role,key);
    if(!row.row())return RichonlineMailMutation::missing;if(row.integer(2)!=0){transaction.commit();return RichonlineMailMutation::duplicate;}
    // Server policy: never silently destroy an unclaimed attachment.
    if(row.integer(0)!=0 && row.integer(1)==0)return RichonlineMailMutation::attachment_pending;
    Statement update(db_,"UPDATE native_mail SET deleted=1 WHERE role_id=? AND key_high=? AND key_low=?");bind_key(update,role,key);update.row();
    audit(db_,username,role,key,"delete","visible","deleted");transaction.commit();return RichonlineMailMutation::changed;
}
RichonlineMailClaimResult Storage::claim_mail(const std::string& username,std::int64_t role,const RichonlineMailClaim48& claim,std::int64_t now){
    if(now<0)throw StorageError("mail_time_invalid");const std::lock_guard lock(mutex_);Transaction transaction(db_);context(profile_,db_,username,role);schema(db_);
    Statement row(db_,"SELECT record_hex,original_token,granted_item,attachment_expires_at,claimed,deleted FROM native_mail WHERE role_id=? AND key_high=? AND key_low=?");bind_key(row,role,claim.key);
    if(!row.row() || row.integer(5)!=0)return {RichonlineMailMutation::missing,{}};
    if(static_cast<std::uint32_t>(row.integer(1))!=claim.attachment_token)return {RichonlineMailMutation::token_mismatch,{}};
    const auto record_json=row.record();if(record_json.at("granted_item").is_null())return {claim.attachment_token==0?RichonlineMailMutation::no_attachment:RichonlineMailMutation::attachment_unresolved,{}};
    const auto item=record_json.at("granted_item").get<std::uint32_t>();
    if(row.integer(4)!=0){transaction.commit();return {RichonlineMailMutation::duplicate,item};}
    const auto expires=row.integer(3);if(expires!=0 && expires<=now)return {RichonlineMailMutation::attachment_expired,{}};
    Statement existing(db_,"SELECT 1 FROM lobby_inventory WHERE username=? AND encoded_item=?");existing.bind(1,username);existing.bind(2,item);
    if(existing.row())return {RichonlineMailMutation::inventory_conflict,{}};
    auto record=decode_richonline_mail_record88(unhex(row.text(0)));record.attachment_token=0; // NEW93 clears mail+40 to zero.
    const auto data=hex(encode_richonline_mail_record88(record).payload);
    Statement insert(db_,"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES(?,?,?)");insert.bind(1,username);insert.bind(2,item);insert.bind(3,expires);insert.row();
    Statement update(db_,"UPDATE native_mail SET claimed=1,record_hex=? WHERE role_id=? AND key_high=? AND key_low=?");update.bind(1,data);update.bind(2,role);update.bind(3,claim.key.high);update.bind(4,claim.key.low);update.row();
    audit(db_,username,role,claim.key,"claim attachment",std::to_string(claim.attachment_token),std::to_string(item));transaction.commit();return {RichonlineMailMutation::changed,item};
}
}
