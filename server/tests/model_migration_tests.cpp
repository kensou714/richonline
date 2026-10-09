#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <iostream>
#include <fstream>
#include <memory>

namespace {
using nlohmann::json;
void check(bool condition,const char* message) { if (!condition) throw std::runtime_error(message); }
class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        sqlite3* raw=nullptr; const auto text=path.u8string();
        const int status=sqlite3_open(reinterpret_cast<const char*>(text.c_str()),&raw);
        database_.reset(raw); check(status==SQLITE_OK,"open isolated database");
    }
    void execute(const char* sql) { check(sqlite3_exec(database_.get(),sql,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture SQL failed"); }
    void constraint(const char* sql) {
        check(sqlite3_exec(database_.get(),sql,nullptr,nullptr,nullptr)==SQLITE_CONSTRAINT,"database constraint must reject invalid write");
    }
    void compare_verifiers(const std::filesystem::path& backup_path) {
        sqlite3_stmt* raw=nullptr;
        check(sqlite3_prepare_v2(database_.get(),"ATTACH DATABASE ? AS verifier_backup",-1,&raw,nullptr)==SQLITE_OK,"prepare backup attachment");
        std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> attach(raw,sqlite3_finalize);
        const auto encoded=backup_path.u8string();
        check(sqlite3_bind_text(attach.get(),1,reinterpret_cast<const char*>(encoded.c_str()),-1,SQLITE_TRANSIENT)==SQLITE_OK,"bind backup path");
        check(sqlite3_step(attach.get())==SQLITE_DONE,"attach existing backup");
        check(rows("SELECT count(*) FROM verifier_backup.accounts old LEFT JOIN main.accounts current ON current.username=old.username "
            "WHERE current.username IS NULL OR current.salt IS NOT old.salt OR current.password_hash IS NOT old.password_hash "
            "OR current.setting_text IS NOT old.setting_text")==json::array({json::array({"0"})}),"existing verifier and settings bytes preserved");
    }
    json rows(const char* sql) {
        sqlite3_stmt* raw=nullptr;
        check(sqlite3_prepare_v2(database_.get(),sql,-1,&raw,nullptr)==SQLITE_OK,"fixture prepare failed");
        std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> statement(raw,sqlite3_finalize);
        auto result=json::array(); int code=0;
        while ((code=sqlite3_step(statement.get()))==SQLITE_ROW) {
            auto row=json::array();
            for (int i=0;i<sqlite3_column_count(statement.get());++i) {
                const auto* value=sqlite3_column_text(statement.get(),i);
                row.push_back(value?json(reinterpret_cast<const char*>(value)):json(nullptr));
            }
            result.push_back(row);
        }
        check(code==SQLITE_DONE,"fixture query failed"); return result;
    }
private:
    std::unique_ptr<sqlite3,decltype(&sqlite3_close)> database_{nullptr,sqlite3_close};
};
void fixture(const std::filesystem::path& path) {
    {
        richnet::Storage original(path,richnet::ClientProfile::original);
        original.dispatch("accounts.create",{{"username","MigrationOwner"},{"password","fixture-only"}});
    }
    Database db(path);
    db.execute("UPDATE metadata SET value='richonline' WHERE key='client_profile';"
        "ALTER TABLE roles ADD COLUMN extra TEXT NOT NULL DEFAULT 'retained';"
        "ALTER TABLE roles ADD COLUMN derived INTEGER GENERATED ALWAYS AS (model+10) VIRTUAL;"
        "UPDATE roles SET coins=3.141592653589793,gold=9007199254740992.0,bank=0.125;"
        "CREATE TABLE extensions(role_id INTEGER PRIMARY KEY REFERENCES roles(role_id) ON DELETE CASCADE,data BLOB);"
        "INSERT INTO extensions VALUES(1,x'0088FE');"
        "CREATE TABLE trigger_events(value INTEGER);"
        "CREATE INDEX custom_role_index ON roles(name) WHERE level>0;"
        "CREATE TRIGGER custom_role_update AFTER UPDATE OF model ON roles BEGIN INSERT INTO trigger_events VALUES(NEW.model); END;"
        "CREATE VIEW role_view AS SELECT role_id,model,extra,derived FROM roles;"
        "INSERT INTO operations VALUES('retain-operation',1,'test','preserve','{}','{}');");
}
json snapshot(Database& db) {
    return json::array({db.rows("SELECT * FROM roles"),db.rows("SELECT * FROM extensions"),
        db.rows("SELECT * FROM audit"),db.rows("SELECT * FROM operations"),
        db.rows("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name IN ('custom_role_index','custom_role_update','role_view') ORDER BY name")});
}
std::filesystem::path backup(const std::filesystem::path& directory) {
    for (const auto& entry:std::filesystem::directory_iterator(directory/"backups"))
        if (entry.path().filename().string().starts_with("before-model-v6-")) return entry.path();
    throw std::runtime_error("migration backup missing");
}
template<class Action> void rejects(Action action,const char* expected) {
    try { action(); } catch (const richnet::StorageError& error) {
        check(std::string(error.what())==expected,"unexpected rejection"); return;
    }
    throw std::runtime_error("expected rejection missing");
}
void preserve_and_expand(const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory); const auto path=directory/"accounts.sqlite3"; fixture(path);
    Database before(path); const auto state=snapshot(before);
    {
        richnet::Storage migrated(path);
        Database after(path);
        check(snapshot(after)==state,"migration preserves rows, extensions, indexes, triggers and view SQL");
        check(after.rows("SELECT value FROM metadata WHERE key='schema_version'")==json::array({json::array({"6"})}),"version promoted");
        check(after.rows("PRAGMA foreign_key_check").empty(),"foreign keys preserved");
        after.execute("PRAGMA foreign_keys=ON");
        after.constraint("UPDATE roles SET model=9");
        after.constraint("INSERT INTO extensions VALUES(999,x'00')");
        for (std::uint32_t model=0;model<=8;++model) migrated.select_model("MigrationOwner",1,model);
        const auto role=migrated.roles_for_username("MigrationOwner").at(0);
        check(role.at("model")==8 && role.at("derived")==18,"new model domain and generated column active");
        check(after.rows("SELECT count(*) FROM trigger_events")==json::array({json::array({"8"})}),"custom trigger retained and active");
        check(after.rows("SELECT count(*) FROM role_view WHERE model=8")==json::array({json::array({"1"})}),"view still resolves");
        rejects([&] { migrated.select_model("MigrationOwner",1,9); },"model_selection_invalid");
        migrated.dispatch("accounts.update",{{"role_id",1},{"expected",role},{"changes",{{"model",7}}},{"reason","profile upper domain"}});
        auto config=migrated.dispatch("config.get",json::object()); config["settings"]["default_role"]["model"]=8;
        migrated.dispatch("config.update",{{"expectedRevision",config.at("revision")},{"settings",config.at("settings")}});
        check(migrated.dispatch("accounts.create",{{"username","NewModel"},{"password","fixture-only"}}).at("account").at("model")==8,"new account profile default accepts model 8");
    }
    Database saved(backup(directory));
    Database(path).compare_verifiers(backup(directory));
    check(snapshot(saved)==state,"pre-migration backup retains exact old snapshot");
    check(saved.rows("SELECT value FROM metadata WHERE key='schema_version'")==json::array({json::array({"5"})}),"backup retains v5 schema");
    saved.constraint("UPDATE roles SET model=5");
    richnet::Storage reopened(path);
    check(reopened.roles_for_username("MigrationOwner").at(0).at("model")==7,"reopen retains upgraded model");
}
void rollback(const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory); const auto path=directory/"accounts.sqlite3"; fixture(path);
    Database db(path);
    db.constraint("UPDATE roles SET model=5");
    db.execute("CREATE TRIGGER block_version BEFORE UPDATE ON metadata WHEN NEW.key='schema_version' "
               "BEGIN SELECT RAISE(ABORT,'injected_migration_failure'); END;");
    const auto state=snapshot(db);
    rejects([&] { richnet::Storage failed(path); },"database_sql_failed");
    check(snapshot(db)==state,"failed migration restores original rows and objects");
    check(db.rows("SELECT value FROM metadata WHERE key='schema_version'")==json::array({json::array({"5"})}),"failed migration retains version");
    check(db.rows("SELECT name FROM sqlite_schema WHERE name='richnet_roles_v6'").empty(),"temporary table rolled back");
    Database saved(backup(directory)); check(snapshot(saved)==state,"failed migration still has intact backup");
    db.execute("DROP TRIGGER block_version");
    richnet::Storage retry(path); check(retry.select_model("MigrationOwner",1,8).at("model")==8,"retry after rollback succeeds");
}
void original_remains_v5(const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory); const auto path=directory/"accounts.sqlite3";
    richnet::Storage original(path,richnet::ClientProfile::original);
    const auto role=original.dispatch("accounts.create",{{"username","OriginalOwner"},{"password","fixture-only"}}).at("account");
    rejects([&] { original.select_model("OriginalOwner",1,5); },"model_selection_invalid");
    rejects([&] { original.dispatch("accounts.update",{{"role_id",1},{"expected",role},{"changes",{{"model",5}}},{"reason","range test"}}); },"role_integer_out_of_range");
    Database db(path);
    check(db.rows("SELECT value FROM metadata WHERE key='schema_version'")==json::array({json::array({"5"})}),"original keeps schema v5");
}
void sequence_preserved(const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory); const auto path=directory/"accounts.sqlite3";
    Database db(path);
    db.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT;"
        "INSERT INTO metadata VALUES('schema_version','5'),('client_profile','richonline');"
        "CREATE TABLE roles(role_id INTEGER PRIMARY KEY AUTOINCREMENT,model INTEGER NOT NULL CHECK(model BETWEEN 0 AND 4)) STRICT;"
        "INSERT INTO roles VALUES(900,2); DELETE FROM roles;");
    richnet::Storage migrated(path);
    db.execute("INSERT INTO roles(model) VALUES(8)");
    check(db.rows("SELECT role_id FROM roles")==json::array({json::array({"901"})}),"AUTOINCREMENT high watermark retained");
}
void backup_failure(const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory); const auto path=directory/"accounts.sqlite3"; fixture(path);
    Database db(path); const auto before=snapshot(db);
    { std::ofstream occupied(directory/"backups"); occupied<<"test blocks backup directory"; }
    bool failed=false;
    try { richnet::Storage rejected(path); } catch (const std::filesystem::filesystem_error&) { failed=true; }
    check(failed,"backup failure blocks migration");
    check(snapshot(db)==before,"failed backup preserves original rows and objects");
    check(db.rows("SELECT value FROM metadata WHERE key='schema_version'")==json::array({json::array({"5"})}),"failed backup retains version");
}
void legacy_python_shape(const std::filesystem::path& directory) {
    std::filesystem::create_directories(directory); const auto path=directory/"accounts.sqlite3";
    Database db(path);
    db.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT;"
        "INSERT INTO metadata VALUES('schema_version','5');"
        "CREATE TABLE roles(role_id INTEGER PRIMARY KEY CHECK(role_id BETWEEN 1 AND 2147483647),"
        "username TEXT NOT NULL REFERENCES accounts(username),name TEXT NOT NULL,"
        "model INTEGER NOT NULL CHECK(model BETWEEN 0 AND 4),level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 20),"
        "experience INTEGER NOT NULL CHECK(experience BETWEEN 0 AND 2147483647),"
        "coins REAL NOT NULL CHECK(coins BETWEEN 0 AND 1.7976931348623157e308),"
        "gold REAL NOT NULL CHECK(gold BETWEEN 0 AND 1.7976931348623157e308),"
        "bank REAL NOT NULL CHECK(bank BETWEEN 0 AND 1.7976931348623157e308),"
        "wins INTEGER NOT NULL DEFAULT 0 CHECK(wins BETWEEN 0 AND 2147483647),"
        "losses INTEGER NOT NULL DEFAULT 0 CHECK(losses BETWEEN 0 AND 2147483647),"
        "draws INTEGER NOT NULL DEFAULT 0 CHECK(draws BETWEEN 0 AND 2147483647),"
        "vip_level INTEGER NOT NULL DEFAULT 0 CHECK(vip_level BETWEEN 0 AND 3),"
        "escapes INTEGER NOT NULL DEFAULT 0 CHECK(escapes BETWEEN 0 AND 2147483647),"
        "purchase_score INTEGER NOT NULL DEFAULT 0 CHECK(purchase_score BETWEEN 0 AND 2147483647)) STRICT;");
    rejects([&] { richnet::Storage refused(path); },"database_client_profile_adoption_required");
    richnet::Storage adopted(path,richnet::ClientProfile::richonline,true);
    adopted.dispatch("accounts.create",{{"username","LegacyShape"},{"password","fixture-only"}});
    check(adopted.select_model("LegacyShape",1,8).at("model")==8,"legacy Python schema migrates with explicit adoption");
    db.constraint("UPDATE roles SET gold=1e999");
    db.constraint("UPDATE roles SET model=9");
}
}
int main() {
    try {
        const auto base=std::filesystem::absolute("model-migration-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        preserve_and_expand(base/"preservation"); std::cout<<"PASS v5-to-v6 preservation, backup and nine-model domain\n";
        rollback(base/"rollback"); std::cout<<"PASS failure after rebuild rolls back rows, objects and version\n";
        original_remains_v5(base/"original"); std::cout<<"PASS original five-model domain remains v5\n";
        sequence_preserved(base/"sequence"); std::cout<<"PASS AUTOINCREMENT high watermark retained\n";
        backup_failure(base/"backup-failure"); std::cout<<"PASS backup failure prevents migration\n";
        legacy_python_shape(base/"legacy-python"); std::cout<<"PASS legacy Python v5 schema and explicit profile adoption\n";
        const auto text=base.u8string(); std::cout<<"Isolated artifacts: "<<std::string(text.begin(),text.end())<<'\n';
        return 0;
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
