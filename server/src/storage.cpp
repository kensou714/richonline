#include "storage.hpp"
#include "storage_detail.hpp"
#include "storage_migration.hpp"
#include <windows.h>
#include <chrono>
#include <memory>

namespace richnet {
using namespace storage_detail;
namespace {
using Database = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;
Database open(const std::filesystem::path& path, int flags) {
    const auto utf8=path.u8string();
    sqlite3* raw=nullptr;
    const int result=sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()),&raw,flags,nullptr);
    Database db(raw,sqlite3_close);
    if (result!=SQLITE_OK) throw StorageError("database_open_failed");
    sqlite3_busy_timeout(db.get(),5000);
    return db;
}
void copy_database(sqlite3* source,const std::filesystem::path& destination) {
    // 使用 SQLite 在线备份接口读取一致快照，不能直接复制仍在使用 WAL 的主数据库。
    std::filesystem::create_directories(destination.parent_path());
    HANDLE reservation=CreateFileW(destination.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (reservation==INVALID_HANDLE_VALUE) throw StorageError("backup_target_exists_or_unavailable");
    CloseHandle(reservation);
    try {
        auto target=open(destination,SQLITE_OPEN_READWRITE);
        sqlite3_backup* job=sqlite3_backup_init(target.get(),"main",source,"main");
        if (!job) throw StorageError("database_backup_init_failed");
        const int step=sqlite3_backup_step(job,-1);
        const int finish=sqlite3_backup_finish(job);
        if (step!=SQLITE_DONE || finish!=SQLITE_OK) throw StorageError("database_backup_failed");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(destination,ignored);
        throw;
    }
}
constexpr const char* schema=R"sql(
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS accounts(username TEXT PRIMARY KEY,salt TEXT NOT NULL,password_hash TEXT NOT NULL,setting_text TEXT) STRICT;
CREATE TABLE IF NOT EXISTS roles(
 role_id INTEGER PRIMARY KEY CHECK(role_id BETWEEN 1 AND 2147483647),
 username TEXT NOT NULL REFERENCES accounts(username),name TEXT NOT NULL,
 model INTEGER NOT NULL CHECK(model BETWEEN 0 AND 4),level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 20),
 experience INTEGER NOT NULL CHECK(experience BETWEEN 0 AND 2147483647),
 coins REAL NOT NULL CHECK(coins>=0),gold REAL NOT NULL CHECK(gold>=0),bank REAL NOT NULL CHECK(bank>=0),
 wins INTEGER NOT NULL DEFAULT 0 CHECK(wins BETWEEN 0 AND 2147483647),
 losses INTEGER NOT NULL DEFAULT 0 CHECK(losses BETWEEN 0 AND 2147483647),
 draws INTEGER NOT NULL DEFAULT 0 CHECK(draws BETWEEN 0 AND 2147483647),
 vip_level INTEGER NOT NULL DEFAULT 0 CHECK(vip_level BETWEEN 0 AND 3),
 escapes INTEGER NOT NULL DEFAULT 0 CHECK(escapes BETWEEN 0 AND 2147483647),
 purchase_score INTEGER NOT NULL DEFAULT 0 CHECK(purchase_score BETWEEN 0 AND 2147483647)) STRICT;
CREATE TABLE IF NOT EXISTS room_records(position INTEGER PRIMARY KEY,record_hex TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,role_id INTEGER NOT NULL,username TEXT NOT NULL,
 field TEXT NOT NULL,old_value TEXT NOT NULL,new_value TEXT NOT NULL,source TEXT NOT NULL,reason TEXT NOT NULL,
 operation_id TEXT NOT NULL,changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT;
CREATE TABLE IF NOT EXISTS operations(operation_id TEXT PRIMARY KEY,role_id INTEGER NOT NULL REFERENCES roles(role_id),
 source TEXT NOT NULL,reason TEXT NOT NULL,request TEXT NOT NULL,result TEXT NOT NULL) STRICT;
INSERT OR IGNORE INTO metadata VALUES('schema_version','5');
INSERT OR IGNORE INTO metadata VALUES('next_role_id','1');
CREATE TABLE IF NOT EXISTS native_settings(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,
 settings TEXT NOT NULL CHECK(json_valid(settings))) STRICT;
)sql";
}

Storage::Storage(std::filesystem::path database_path, ClientProfile profile, bool adopt_untagged_profile)
    :path_(std::filesystem::absolute(database_path)),profile_(profile) {
    std::filesystem::create_directories(path_.parent_path());
    auto owned=open(path_,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX);
    execute(owned.get(),"PRAGMA foreign_keys=OFF; PRAGMA journal_mode=WAL;");
    Transaction transaction(owned.get());
    bool fresh=false;
    {
        Statement tables(owned.get(),"SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
        tables.row(); fresh=tables.integer(0)==0;
    }
    execute(owned.get(),schema);
    std::string version;
    {
        Statement stored_version(owned.get(),"SELECT value FROM metadata WHERE key='schema_version'");
        if (!stored_version.row()) throw StorageError("schema_version_unsupported");
        version=stored_version.text(0);
        if (version!="5" && version!="6")
            throw StorageError("schema_version_unsupported");
        Statement stored_profile(owned.get(),"SELECT value FROM metadata WHERE key='client_profile'");
        if (stored_profile.row()) {
            if (stored_profile.text(0)!=client_profile_name(profile_)) throw StorageError("database_client_profile_mismatch");
        } else {
            // 旧库密码校验值没有编码来源标签；接管无标签库必须由管理员显式指定版本。
            if (!fresh && !adopt_untagged_profile) throw StorageError("database_client_profile_adoption_required");
            Statement tag(owned.get(),"INSERT INTO metadata(key,value) VALUES('client_profile',?)");
            tag.bind(1,std::string(client_profile_name(profile_))); tag.row();
        }
        if (version=="6" && profile_!=ClientProfile::richonline) throw StorageError("schema_version_unsupported");
    }
    if (profile_==ClientProfile::richonline && version=="5") {
        if (!fresh) {
            auto original=open(path_,SQLITE_OPEN_READONLY);
            const auto ticks=std::chrono::system_clock::now().time_since_epoch().count();
            copy_database(original.get(),path_.parent_path()/"backups"/("before-model-v6-"+std::to_string(ticks)+".sqlite3"));
        }
        migrate_richonline_models(owned.get());
    }
    if (profile_==ClientProfile::richonline) execute(owned.get(),R"sql(
CREATE TABLE IF NOT EXISTS lobby_inventory(
 inventory_id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL REFERENCES accounts(username),
 encoded_item INTEGER NOT NULL CHECK(encoded_item BETWEEN 1 AND 4294967295),
 expires_at INTEGER NOT NULL CHECK(expires_at>=0)) STRICT;
CREATE TABLE IF NOT EXISTS lobby_equipment(
 role_id INTEGER NOT NULL REFERENCES roles(role_id),
 slot INTEGER NOT NULL CHECK(slot BETWEEN 0 AND 31),
 encoded_item INTEGER NOT NULL CHECK(encoded_item BETWEEN 1 AND 4294967295),
 PRIMARY KEY(role_id,slot)) STRICT;
)sql");
    if (profile_==ClientProfile::richonline) {
        // 每次购买都是一个拥有实例；完整道具键相同不代表同一个实例。
        bool has_instance_id=false;
        {
            Statement columns(owned.get(),"PRAGMA table_info(lobby_inventory)");
            while (columns.row()) if (columns.text(1)=="inventory_id") has_instance_id=true;
        }
        if (!has_instance_id) execute(owned.get(),R"sql(
ALTER TABLE lobby_inventory RENAME TO lobby_inventory_legacy;
CREATE TABLE lobby_inventory(
 inventory_id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL REFERENCES accounts(username),
 encoded_item INTEGER NOT NULL CHECK(encoded_item BETWEEN 1 AND 4294967295),
 expires_at INTEGER NOT NULL CHECK(expires_at>=0)) STRICT;
INSERT INTO lobby_inventory(username,encoded_item,expires_at)
 SELECT username,encoded_item,expires_at FROM lobby_inventory_legacy ORDER BY rowid;
DROP TABLE lobby_inventory_legacy;
)sql");
        execute(owned.get(),"CREATE INDEX IF NOT EXISTS lobby_inventory_owner_key ON lobby_inventory(username,encoded_item)");
    }
    Statement settings(owned.get(),"INSERT OR IGNORE INTO native_settings VALUES(1,1,?)");
    settings.bind(1,default_settings().dump()); settings.row();
    transaction.commit();
    execute(owned.get(),"PRAGMA foreign_keys=ON");
    db_=owned.release();
}
Storage::~Storage() { sqlite3_close(db_); }

nlohmann::json Storage::dispatch(std::string command,const nlohmann::json& payload) {
    const std::lock_guard lock(mutex_);
    if (!payload.is_object()) throw StorageError("payload_object_required");
    try {
        if (command=="accounts.list") return list_accounts(payload);
        if (command=="accounts.create") return create_account(payload);
        if (command=="accounts.update") return update_account(payload);
        if (command=="config.get") { require_keys(payload,{}); return get_config(); }
        if (command=="config.update") return update_config(payload);
        if (command=="database.backup") { require_keys(payload,{}); return backup(); }
    } catch (const nlohmann::json::exception&) { throw StorageError("request_value_invalid"); }
    throw StorageError("command_unknown");
}

nlohmann::json Storage::backup() {
    const auto ticks=std::chrono::system_clock::now().time_since_epoch().count();
    const auto destination=path_.parent_path()/"backups"/("accounts-"+std::to_string(ticks)+".sqlite3");
    copy_database(db_,destination);
    const auto utf8=destination.u8string();
    return {{"path",std::string(reinterpret_cast<const char*>(utf8.data()),utf8.size())}};
}

std::filesystem::path Storage::import_database(const std::filesystem::path& source,
                                              const std::filesystem::path& destination) {
    const auto absolute_destination=std::filesystem::absolute(destination);
    auto original=open(source,SQLITE_OPEN_READONLY);
    Statement version(original.get(),"SELECT value FROM metadata WHERE key='schema_version'");
    if (!version.row() || (version.text(0)!="5" && version.text(0)!="6")) throw StorageError("schema_version_unsupported");
    copy_database(original.get(),absolute_destination);
    return absolute_destination;
}
}
