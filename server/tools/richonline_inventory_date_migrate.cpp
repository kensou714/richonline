#include "storage_detail.hpp"
#include "richonline_inventory_date.hpp"
#include "richonline_inventory_date_patch.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <map>
#include <set>

namespace {
using namespace richnet;
using namespace storage_detail;
using Json=nlohmann::json;
std::string utf8(const std::filesystem::path& path){const auto text=path.u8string();return {reinterpret_cast<const char*>(text.data()),text.size()};}
std::filesystem::path utf8_path(const std::string& value){return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(value.data()),value.size()));}
void require_no_journal(const std::filesystem::path& path){
    // Raw main-file hashes cannot observe a pending WAL or rollback journal.
    // Refuse even an empty sidecar; an operator must first stop its writer.
    for(const auto* suffix:{L"-wal",L"-journal",L"-shm"})
        if(std::filesystem::exists(std::filesystem::path(path.wstring()+suffix)))
            throw StorageError("date_migration_database_journal_present");
}
struct ReadLease {
    HANDLE handle=INVALID_HANDLE_VALUE;
    explicit ReadLease(const std::filesystem::path& path){
        // Keep an offline source stable throughout hashing and backup. This
        // sharing mode refuses existing writers and prevents a new writer.
        handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(handle==INVALID_HANDLE_VALUE)throw StorageError("date_migration_source_open_or_writer_active");
    }
    ~ReadLease(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
    ReadLease(const ReadLease&)=delete;ReadLease& operator=(const ReadLease&)=delete;
};
Bytes file_bytes(const std::filesystem::path& path){
    std::ifstream file(path,std::ios::binary|std::ios::ate);if(!file)throw StorageError("date_migration_file_open_failed");
    const auto size=file.tellg();if(size<=0||size>64*1024*1024)throw StorageError("date_migration_file_size_invalid");
    Bytes data(static_cast<std::size_t>(size));file.seekg(0);if(!file.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(data.size())))throw StorageError("date_migration_file_read_failed");return data;
}
struct Database {
    sqlite3* db{};
    Database(const std::filesystem::path& path,bool write,bool immutable=false){
        auto text=utf8(path);int flags=write?SQLITE_OPEN_READWRITE:SQLITE_OPEN_READONLY;
        if(immutable){
            if(write)throw StorageError("date_migration_immutable_write_invalid");
            constexpr char hex[]="0123456789ABCDEF";std::string uri="file:";
            for(const auto character:text){const auto value=static_cast<unsigned char>(character);
                if((value>='a'&&value<='z')||(value>='A'&&value<='Z')||(value>='0'&&value<='9')||value=='/'||value==':'||value=='-'||value=='_'||value=='.')uri.push_back(character);
                else{uri.push_back('%');uri.push_back(hex[value>>4U]);uri.push_back(hex[value&15U]);}
            }
            text=uri+"?immutable=1";flags|=SQLITE_OPEN_URI;
        }
        if(sqlite3_open_v2(text.c_str(),&db,flags,nullptr)!=SQLITE_OK){if(db)sqlite3_close(db);db=nullptr;throw StorageError("date_migration_database_open_failed");}
        sqlite3_busy_timeout(db,1000);
    }
    ~Database(){if(db)sqlite3_close(db);}
};
void new_file(const std::filesystem::path& path,View bytes={}){
    const auto handle=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(handle==INVALID_HANDLE_VALUE)throw StorageError("date_migration_destination_exists_or_invalid");
    DWORD count=0;const bool okay=(bytes.empty()||(WriteFile(handle,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr)&&count==bytes.size()))&&FlushFileBuffers(handle);CloseHandle(handle);
    if(!okay){std::error_code error;std::filesystem::remove(path,error);throw StorageError("date_migration_destination_write_failed");}
}
void backup(sqlite3* source,const std::filesystem::path& path){
    new_file(path);
    try{
        Database target(path,true);auto* handle=sqlite3_backup_init(target.db,"main",source,"main");if(!handle)throw StorageError("date_migration_backup_init_failed");
        const auto result=sqlite3_backup_step(handle,-1);const auto finish=sqlite3_backup_finish(handle);
        if(result!=SQLITE_DONE||finish!=SQLITE_OK)throw StorageError("date_migration_backup_failed");
        execute(target.db,"PRAGMA journal_mode=DELETE;");
        Statement integrity(target.db,"PRAGMA integrity_check");if(!integrity.row()||integrity.text(0)!="ok")throw StorageError("date_migration_backup_integrity_failed");
    }catch(...){std::error_code error;std::filesystem::remove(path,error);throw;}
}
bool table(sqlite3* db,const char* name){Statement row(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name=?");row.bind(1,name);return row.row();}
std::string metadata(sqlite3* db,const char* key,const std::string& initial){Statement row(db,"SELECT value FROM metadata WHERE key=?");row.bind(1,key);return row.row()?row.text(0):initial;}
struct Mapping {std::string owner;std::uint32_t old_key,new_key;};
struct Plan {Json report;std::vector<Mapping> aliases;};
Plan plan(sqlite3* db,std::int64_t now){
    if(metadata(db,"client_profile","")!="richonline")throw StorageError("date_migration_profile_invalid");
    if(metadata(db,"inventory_date_version","original-2005")!="original-2005")throw StorageError("date_migration_source_mode_invalid");
    Plan result{{{"from","original-2005"},{"to",richonline_inventory_compatibility_id},{"utc_now",now},{"mappings",Json::array()},{"unresolved",Json::array()},
        {"historical_retained",0},{"test_certificate13_retained",0},{"row_counts",Json::object()},{"immutable_receipts_preserved",true},{"source_modified",false}}, {}};
    for(const auto* name:{"accounts","roles","lobby_inventory","lobby_equipment","native_mail","native_mall_purchases","native_mall_activations","audit","operations"}){
        if(!table(db,name))continue;const auto query="SELECT count(*) FROM "+std::string(name);Statement count(db,query.c_str());
        if(!count.row())throw StorageError("date_migration_count_missing");result.report["row_counts"][name]=count.integer(0);
    }
    Statement foreign_keys(db,"PRAGMA foreign_key_check");
    while(foreign_keys.row())result.report["unresolved"].push_back({{"reason","source_foreign_key_invalid"},{"row",foreign_keys.record()}});
    std::map<std::pair<std::string,std::uint32_t>,std::uint32_t> mapping;
    std::map<std::pair<std::string,std::uint32_t>,std::uint32_t> reverse;
    const auto consider=[&](const std::string& kind,const std::string& owner,std::uint32_t old,std::int64_t expiry){
        if(old==13){result.report["test_certificate13_retained"]=result.report["test_certificate13_retained"].get<unsigned>()+1;return;}
        if(expiry==0){if((old&0x3ffe0000U)!=0)result.report["unresolved"].push_back({{"kind",kind},{"owner",owner},{"old_key",old},{"reason","untimed_item_has_legacy_date"}});return;}
        std::uint32_t next=old;
        try{next=richonline_inventory_key_from_expiry(old,expiry,RichonlineInventoryDateVersion::compat_2021_v1);}
        catch(const CodecError& error){
            if(expiry<=now){result.report["historical_retained"]=result.report["historical_retained"].get<unsigned>()+1;return;}
            result.report["unresolved"].push_back({{"kind",kind},{"owner",owner},{"old_key",old},{"expires_at",expiry},{"reason",error.what()}});return;
        }
        const auto key=std::make_pair(owner,old);const auto prior=mapping.find(key);
        if(prior!=mapping.end()&&prior->second!=next){result.report["unresolved"].push_back({{"kind",kind},{"owner",owner},{"old_key",old},{"reason","same_key_distinct_expiries"}});return;}
        const auto destination=std::make_pair(owner,next);const auto collision=reverse.find(destination);
        if(collision!=reverse.end()&&collision->second!=old){result.report["unresolved"].push_back({{"owner",owner},{"old_key",old},{"new_key",next},{"reason","new_key_collision"}});return;}
        mapping[key]=next;reverse[destination]=old;
    };
    if(table(db,"lobby_inventory")){
        Statement rows(db,"SELECT username,encoded_item,expires_at FROM lobby_inventory ORDER BY username,encoded_item");
        while(rows.row())consider("inventory",rows.text(0),static_cast<std::uint32_t>(rows.integer(1)),rows.integer(2));
    }
    if(table(db,"native_mail")){
        Statement rows(db,"SELECT r.username,m.granted_item,m.attachment_expires_at FROM native_mail m JOIN roles r ON r.role_id=m.role_id WHERE m.granted_item IS NOT NULL AND m.claimed=0 AND m.deleted=0");
        while(rows.row())consider("mail_grant",rows.text(0),static_cast<std::uint32_t>(rows.integer(1)),rows.integer(2));
    }
    // Receipts stay immutable. Their aliases remain useful after an item was
    // removed from the inventory, so include their authoritative expiry too.
    if(table(db,"native_mall_purchases")){
        Statement rows(db,"SELECT username,owned_key,expires_at FROM native_mall_purchases");
        while(rows.row())consider("purchase_receipt",rows.text(0),static_cast<std::uint32_t>(rows.integer(1)),rows.integer(2));
    }
    if(table(db,"native_mall_activations")){
        Statement rows(db,"SELECT username,new_key,expires_at FROM native_mall_activations");
        while(rows.row())consider("activation_receipt",rows.text(0),static_cast<std::uint32_t>(rows.integer(1)),rows.integer(2));
    }
    // Check after inventory AND mail mappings exist. A target overlapping any
    // old source would make sequential UPDATEs cascade, so refuse this case.
    for(const auto& [source,next]:mapping){
        if(source.second!=next&&mapping.contains({source.first,next}))
            result.report["unresolved"].push_back({{"owner",source.first},{"old_key",source.second},{"new_key",next},{"reason","target_overlaps_source_key"}});
    }
    const auto retained_collision=[&](const std::string& owner,std::uint32_t old){
        const auto target=reverse.find({owner,old});
        if(target!=reverse.end()&&target->second!=old&&!mapping.contains({owner,old}))
            result.report["unresolved"].push_back({{"owner",owner},{"new_key",old},{"reason","collision_with_retained_item"}});
    };
    if(table(db,"lobby_inventory")){
        Statement rows(db,"SELECT username,encoded_item FROM lobby_inventory");
        while(rows.row())retained_collision(rows.text(0),static_cast<std::uint32_t>(rows.integer(1)));
    }
    if(table(db,"native_mail")){
        Statement rows(db,"SELECT r.username,m.granted_item FROM native_mail m JOIN roles r ON r.role_id=m.role_id WHERE m.granted_item IS NOT NULL AND m.claimed=0 AND m.deleted=0");
        while(rows.row())retained_collision(rows.text(0),static_cast<std::uint32_t>(rows.integer(1)));
    }
    if(table(db,"lobby_equipment")){
        Statement rows(db,"SELECT e.role_id,e.slot,e.encoded_item FROM lobby_equipment e LEFT JOIN roles r ON r.role_id=e.role_id LEFT JOIN lobby_inventory i ON i.username=r.username AND i.encoded_item=e.encoded_item WHERE r.role_id IS NULL OR i.encoded_item IS NULL");
        while(rows.row())result.report["unresolved"].push_back({{"role_id",rows.integer(0)},{"slot",rows.integer(1)},{"old_key",rows.integer(2)},{"reason","orphan_equipment"}});
    }
    for(const auto& [key,next]:mapping)if(key.second!=next){result.aliases.push_back({key.first,key.second,next});result.report["mappings"].push_back({{"owner",key.first},{"old_key",key.second},{"new_key",next}});}
    result.report["ready"]=result.report["unresolved"].empty();return result;
}
void apply(sqlite3* db,const Plan& plan,const std::string& migration,const std::filesystem::path& preserved,const std::string& backup_hash){
    if(!plan.report.at("ready").get<bool>())throw StorageError("date_migration_preflight_unresolved");
    Transaction transaction(db);
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS inventory_key_aliases(username TEXT NOT NULL,old_key INTEGER NOT NULL,new_key INTEGER NOT NULL,
      old_version INTEGER NOT NULL,new_version INTEGER NOT NULL,migration_id TEXT NOT NULL,UNIQUE(username,old_key,new_version)) STRICT;
      CREATE TABLE IF NOT EXISTS inventory_date_mail_receipts(operation_id TEXT PRIMARY KEY,username TEXT NOT NULL,original_key INTEGER NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS inventory_date_migrations(migration_id TEXT PRIMARY KEY,backup_path TEXT NOT NULL,backup_sha256 TEXT NOT NULL,plan_json TEXT NOT NULL) STRICT;)sql");
    for(const auto& map:plan.aliases){
        Statement inventory(db,"UPDATE lobby_inventory SET encoded_item=? WHERE username=? AND encoded_item=?");inventory.bind(1,map.new_key);inventory.bind(2,map.owner);inventory.bind(3,map.old_key);inventory.row();
        Statement equipment(db,"UPDATE lobby_equipment SET encoded_item=? WHERE encoded_item=? AND role_id IN(SELECT role_id FROM roles WHERE username=?)");equipment.bind(1,map.new_key);equipment.bind(2,map.old_key);equipment.bind(3,map.owner);equipment.row();
        if(table(db,"native_mail")){
            Statement originals(db,"INSERT INTO inventory_date_mail_receipts SELECT m.operation_id,r.username,m.granted_item FROM native_mail m JOIN roles r ON r.role_id=m.role_id WHERE r.username=? AND m.granted_item=? AND m.claimed=0 AND m.deleted=0");originals.bind(1,map.owner);originals.bind(2,map.old_key);originals.row();
            Statement mail(db,"UPDATE native_mail SET granted_item=? WHERE granted_item=? AND claimed=0 AND deleted=0 AND role_id IN(SELECT role_id FROM roles WHERE username=?)");mail.bind(1,map.new_key);mail.bind(2,map.old_key);mail.bind(3,map.owner);mail.row();
        }
        Statement alias(db,"INSERT INTO inventory_key_aliases VALUES(?,?,?,2005,2021,?)");alias.bind(1,map.owner);alias.bind(2,map.old_key);alias.bind(3,map.new_key);alias.bind(4,migration);alias.row();
    }
    Statement record(db,"INSERT INTO inventory_date_migrations VALUES(?,?,?,?)");record.bind(1,migration);record.bind(2,utf8(preserved));record.bind(3,backup_hash);record.bind(4,plan.report.dump());record.row();
    Statement mode(db,"INSERT INTO metadata(key,value) VALUES('inventory_date_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");mode.bind(1,std::string(richonline_inventory_compatibility_id));mode.row();
    for(const auto& [name,expected]:plan.report.at("row_counts").items()){
        const auto query="SELECT count(*) FROM "+name;Statement count(db,query.c_str());
        if(!count.row()||count.integer(0)!=expected.get<std::int64_t>())throw StorageError("date_migration_row_count_changed");
    }
    Statement fk(db,"PRAGMA foreign_key_check");if(fk.row())throw StorageError("date_migration_foreign_key_invalid");
    transaction.commit();
}
}
int wmain(int argc,wchar_t** argv){try{
    const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if(argc==4&&std::wstring_view(argv[1])==L"rollback-copy"){
        const auto source=std::filesystem::absolute(argv[2]).lexically_normal(),target=std::filesystem::absolute(argv[3]).lexically_normal();
        ReadLease source_lease(source);
        require_no_journal(source);
        const auto manifest_path=std::filesystem::path(source.wstring()+L".datemigration.json");std::ifstream file(manifest_path);if(!file)throw StorageError("date_migration_manifest_missing");const auto manifest=Json::parse(file);
        if(richonline_date_image_sha256(file_bytes(source))!=manifest.at("migrated_sha256").get<std::string>())throw StorageError("date_migration_changed_since_commit_refuse_rollback");
        const auto preserved=utf8_path(manifest.at("backup_path").get<std::string>());
        ReadLease backup_lease(preserved);
        require_no_journal(preserved);
        if(richonline_date_image_sha256(file_bytes(preserved))!=manifest.at("backup_sha256").get<std::string>())throw StorageError("date_migration_backup_hash_mismatch");
        Database backup_db(preserved,false);backup(backup_db.db,target);std::cout<<Json{{"rolled_back_to_new_copy",utf8(target)},{"source_modified",false}}.dump()<<'\n';return 0;
    }
    const bool dry=argc==4&&std::wstring_view(argv[1])==L"plan",write=argc==5&&std::wstring_view(argv[1])==L"migrate-copy";
    if(!dry&&!write)throw StorageError("usage: plan SOURCE VERIFIED_CLIENT | migrate-copy SOURCE NEW_COPY VERIFIED_CLIENT | rollback-copy MIGRATED NEW_COPY");
    const auto client=std::filesystem::path(argv[write?4:3]);const auto client_image=file_bytes(client);if(!richonline_date_compatibility_image_valid(client_image))throw StorageError("date_migration_client_not_verified");
    const auto source=std::filesystem::absolute(argv[2]).lexically_normal();ReadLease source_lease(source);require_no_journal(source);
    // A closed WAL-mode database can otherwise create new sidecars even on a
    // read-only SQLite open. The read lease and prior sidecar refusal make this
    // immutable URI safe, and guarantee a truly read-only dry-run.
    Database original(source,false,true);execute(original.db,"BEGIN;");
    const auto planned=plan(original.db,now);
    if(dry){std::cout<<planned.report.dump(2)<<'\n';return planned.report.at("ready").get<bool>()?0:2;}
    if(!planned.report.at("ready").get<bool>())throw StorageError("date_migration_preflight_unresolved");
    const auto target=std::filesystem::absolute(argv[3]).lexically_normal();const auto preserved=std::filesystem::path(target.wstring()+L".pre-date.sqlite3");
    const auto manifest_path=std::filesystem::path(target.wstring()+L".datemigration.json");
    if(source==target||std::filesystem::exists(target)||std::filesystem::exists(preserved)||std::filesystem::exists(manifest_path))throw StorageError("date_migration_destination_must_be_new");
    backup(original.db,preserved);const auto backup_hash=richonline_date_image_sha256(file_bytes(preserved));
    Database saved(preserved,false);backup(saved.db,target);
    try{Database destination(target,true);apply(destination.db,planned,utf8(target),preserved,backup_hash);}catch(...){std::error_code error;std::filesystem::remove(target,error);throw;}
    const Json manifest{{"compatibility_id",richonline_inventory_compatibility_id},{"source_path",utf8(source)},{"migrated_path",utf8(target)},
        {"verified_client_sha256",richonline_date_image_sha256(client_image)},
        {"backup_path",utf8(preserved)},{"backup_sha256",backup_hash},{"migrated_sha256",richonline_date_image_sha256(file_bytes(target))},
        {"source_modified",false},{"plan",planned.report}};
    const auto text=manifest.dump(2)+"\n";new_file(manifest_path,Bytes(text.begin(),text.end()));std::cout<<manifest.dump()<<'\n';return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
