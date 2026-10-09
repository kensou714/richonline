#include "blacklist_store.hpp"

#include <sqlite3.h>
#include <algorithm>
#include <string_view>

namespace richnet {
namespace {
using View = std::span<const std::uint8_t>;

void validate_name(View name) {
    if (name.empty() || name.size()>32 || std::find(name.begin(),name.end(),0)!=name.end())
        throw BlacklistStoreError("blacklist_name_invalid");
}

void validate_key(View owner, View digest) {
    validate_name(owner);
    if (digest.size()!=32 || !std::all_of(digest.begin(),digest.end(),[](auto byte) {
        return (byte>='0' && byte<='9') || (byte>='a' && byte<='f');
    })) throw BlacklistStoreError("blacklist_digest_invalid");
}

void checked(int result) {
    if (result!=SQLITE_OK) throw BlacklistStoreError("blacklist_database_error_"+std::to_string(result));
}

class Statement {
public:
    Statement(sqlite3* db, const char* sql) {
        const auto result=sqlite3_prepare_v2(db,sql,-1,&statement_,nullptr);
        if (result!=SQLITE_OK) {
            sqlite3_finalize(statement_);
            checked(result);
        }
    }
    ~Statement() { sqlite3_finalize(statement_); }
    Statement(const Statement&)=delete;
    Statement& operator=(const Statement&)=delete;
    void bind(int index, View value) {
        checked(sqlite3_bind_blob(statement_,index,value.data(),static_cast<int>(value.size()),SQLITE_TRANSIENT));
    }
    void bind(int index, bool value) { checked(sqlite3_bind_int(statement_,index,value?1:0)); }
    bool named_column(std::string_view name) const {
        const auto* text=sqlite3_column_text(statement_,1);
        return text && name==reinterpret_cast<const char*>(text);
    }
    bool enabled() const {
        const auto value=sqlite3_column_int(statement_,1);
        if (sqlite3_column_type(statement_,1)!=SQLITE_INTEGER || (value!=0 && value!=1))
            throw BlacklistStoreError("blacklist_database_row_invalid");
        return value!=0;
    }
    bool row() {
        const auto result=sqlite3_step(statement_);
        if (result==SQLITE_ROW) return true;
        if (result==SQLITE_DONE) return false;
        checked(result);
        return false;
    }
    std::vector<std::uint8_t> target() const {
        if (sqlite3_column_type(statement_,0)!=SQLITE_BLOB)
            throw BlacklistStoreError("blacklist_database_row_invalid");
        const auto count=sqlite3_column_bytes(statement_,0);
        const auto* data=static_cast<const std::uint8_t*>(sqlite3_column_blob(statement_,0));
        if (count<1 || count>32 || !data) throw BlacklistStoreError("blacklist_database_row_invalid");
        const View value(data,static_cast<std::size_t>(count));
        validate_name(value);
        return {value.begin(),value.end()};
    }
private:
    sqlite3_stmt* statement_{};
};
}

BlacklistStore::BlacklistStore(const std::filesystem::path& path) {
    if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path());
    const auto encoded=path.u8string();
    const auto result=sqlite3_open_v2(reinterpret_cast<const char*>(encoded.c_str()),&db_,
        SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,nullptr);
    try {
        checked(result);
        checked(sqlite3_busy_timeout(db_,5000));
        checked(sqlite3_exec(db_,"BEGIN IMMEDIATE",nullptr,nullptr,nullptr));
        checked(sqlite3_exec(db_,
            "CREATE TABLE IF NOT EXISTS blacklist ("
            "owner BLOB NOT NULL CHECK(typeof(owner)='blob' AND length(owner) BETWEEN 1 AND 32 AND instr(owner,x'00')=0),"
            "digest BLOB NOT NULL CHECK(typeof(digest)='blob' AND length(digest)=32 "
                "AND CAST(digest AS TEXT) NOT GLOB '*[^0-9a-f]*' AND instr(digest,x'00')=0),"
            "target BLOB NOT NULL CHECK(typeof(target)='blob' AND length(target) BETWEEN 1 AND 32 AND instr(target,x'00')=0),"
            "enabled INTEGER NOT NULL DEFAULT 1 CHECK(typeof(enabled)='integer' AND enabled IN(0,1)),"
            "PRIMARY KEY(owner,digest,target)) WITHOUT ROWID",nullptr,nullptr,nullptr));
        bool has_enabled=false;
        {
            Statement columns(db_,"PRAGMA table_info(blacklist)");
            while (columns.row()) has_enabled=columns.named_column("enabled") || has_enabled;
        }
        if (!has_enabled) checked(sqlite3_exec(db_,
            "ALTER TABLE blacklist ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 "
            "CHECK(typeof(enabled)='integer' AND enabled IN(0,1))",nullptr,nullptr,nullptr));
        checked(sqlite3_exec(db_,"COMMIT",nullptr,nullptr,nullptr));
    } catch (...) {
        if (db_ && !sqlite3_get_autocommit(db_)) sqlite3_exec(db_,"ROLLBACK",nullptr,nullptr,nullptr);
        sqlite3_close(db_); db_=nullptr;
        throw;
    }
}

BlacklistStore::~BlacklistStore() { sqlite3_close(db_); }

std::vector<BlacklistEntry> BlacklistStore::list(View owner, View digest) {
    validate_key(owner,digest);
    const std::lock_guard lock(mutex_);
    Statement select(db_,"SELECT target,enabled FROM blacklist WHERE owner=? AND digest=? ORDER BY target");
    select.bind(1,owner); select.bind(2,digest);
    std::vector<BlacklistEntry> result;
    while (select.row()) result.push_back({select.target(),select.enabled()});
    return result;
}

void BlacklistStore::add(View owner, View digest, View target) {
    validate_key(owner,digest); validate_name(target);
    const std::lock_guard lock(mutex_);
    Statement insert(db_,"INSERT INTO blacklist(owner,digest,target) VALUES(?,?,?) ON CONFLICT(owner,digest,target) DO NOTHING");
    insert.bind(1,owner); insert.bind(2,digest); insert.bind(3,target);
    insert.row();
}

bool BlacklistStore::remove(View owner, View digest, View target) {
    validate_key(owner,digest); validate_name(target);
    const std::lock_guard lock(mutex_);
    Statement erase(db_,"DELETE FROM blacklist WHERE owner=? AND digest=? AND target=?");
    erase.bind(1,owner); erase.bind(2,digest); erase.bind(3,target);
    erase.row();
    return sqlite3_changes(db_)!=0;
}

void BlacklistStore::add_enabled(View owner, View digest, View target) {
    validate_key(owner,digest); validate_name(target);
    const std::lock_guard lock(mutex_);
    Statement insert(db_,"INSERT INTO blacklist(owner,digest,target,enabled) VALUES(?,?,?,1) ON CONFLICT(owner,digest,target) DO UPDATE SET enabled=1");
    insert.bind(1,owner); insert.bind(2,digest); insert.bind(3,target);
    insert.row();
}

bool BlacklistStore::set_enabled(View owner, View digest, View target, bool enabled) {
    validate_key(owner,digest); validate_name(target);
    const std::lock_guard lock(mutex_);
    Statement update(db_,"UPDATE blacklist SET enabled=? WHERE owner=? AND digest=? AND target=?");
    update.bind(1,enabled); update.bind(2,owner); update.bind(3,digest); update.bind(4,target);
    update.row();
    return sqlite3_changes(db_)!=0;
}
}
