#include "storage_detail.hpp"
#include "storage_migration.hpp"
#include <regex>
#include <optional>
#include <string>
#include <vector>

namespace richnet::storage_detail {
namespace {
std::string identifier(const std::string& name) {
    std::string result="\"";
    for (const char character:name) {
        result+=character;
        if (character=='\"') result+='\"';
    }
    return result+'\"';
}
void check_integrity(sqlite3* database) {
    Statement foreign_keys(database,"PRAGMA foreign_key_check");
    if (foreign_keys.row()) throw StorageError("migration_foreign_key_check_failed");
    Statement integrity(database,"PRAGMA integrity_check");
    if (!integrity.row() || integrity.text(0)!="ok" || integrity.row())
        throw StorageError("migration_integrity_check_failed");
}
}

void migrate_richonline_models(sqlite3* database) {
    // 只在调用方事务中重建已识别的表结构；异常由事务回滚，不猜测未知数据库布局。
    if (sqlite3_get_autocommit(database)!=0) throw StorageError("migration_transaction_required");
    Statement foreign_keys(database,"PRAGMA foreign_keys");
    if (!foreign_keys.row() || foreign_keys.integer(0)!=0) throw StorageError("migration_foreign_keys_must_be_disabled");
    check_integrity(database);
    std::string original;
    {
        Statement schema(database,"SELECT sql FROM sqlite_schema WHERE type='table' AND name='roles'");
        if (!schema.row()) throw StorageError("migration_roles_table_missing");
        original=schema.text(0);
    }
    const std::regex declaration(R"(^CREATE\s+TABLE\s+(?:"roles"|roles)\s*\()",std::regex::icase);
    const std::regex model_check(R"(\bmodel\s+INTEGER\s+NOT\s+NULL\s+CHECK\s*\(\s*model\s+BETWEEN\s+0\s+AND\s+4\s*\))",std::regex::icase);
    if (!std::regex_search(original,declaration) ||
        std::distance(std::sregex_iterator(original.begin(),original.end(),model_check),std::sregex_iterator())!=1)
        throw StorageError("migration_roles_schema_unrecognized");
    auto replacement=std::regex_replace(original,declaration,"CREATE TABLE richnet_roles_v6(",std::regex_constants::format_first_only);
    replacement=std::regex_replace(replacement,model_check,"model INTEGER NOT NULL CHECK(model BETWEEN 0 AND 8)",std::regex_constants::format_first_only);
    std::vector<std::string> dependent_sql;
    // 重建角色表时保留自定义索引和触发器，避免扩大模型范围却丢失原有约束行为。
    {
        Statement objects(database,"SELECT sql FROM sqlite_schema WHERE tbl_name='roles' AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name");
        while (objects.row()) dependent_sql.push_back(objects.text(0));
    }
    std::optional<std::int64_t> sequence;
    {
        Statement exists(database,"SELECT 1 FROM sqlite_schema WHERE type='table' AND name='sqlite_sequence'");
        if (exists.row()) {
            Statement current(database,"SELECT seq FROM sqlite_sequence WHERE name='roles'");
            if (current.row()) sequence=current.integer(0);
        }
    }
    std::string columns;
    {
        Statement info(database,"SELECT name FROM pragma_table_xinfo('roles') WHERE hidden=0 ORDER BY cid");
        while (info.row()) {
            if (!columns.empty()) columns+=',';
            columns+=identifier(info.text(0));
        }
    }
    if (columns.empty()) throw StorageError("migration_roles_columns_missing");
    execute(database,replacement.c_str());
    execute(database,("INSERT INTO richnet_roles_v6("+columns+") SELECT "+columns+" FROM roles").c_str());
    execute(database,"DROP TABLE roles");
    execute(database,"PRAGMA legacy_alter_table=ON");
    execute(database,"ALTER TABLE richnet_roles_v6 RENAME TO roles");
    execute(database,"PRAGMA legacy_alter_table=OFF");
    for (const auto& sql:dependent_sql) execute(database,sql.c_str());
    if (sequence) {
        Statement restore(database,"UPDATE sqlite_sequence SET seq=? WHERE name='roles'");
        restore.bind(1,*sequence); restore.row();
    }
    check_integrity(database);
    execute(database,"UPDATE metadata SET value='6' WHERE key='schema_version'");
}
}
