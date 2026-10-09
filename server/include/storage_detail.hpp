#pragma once

// 持久层内部工具：封装 SQLite 语句、事务以及角色和配置字段校验。

#include "storage.hpp"
#include <sqlite3.h>
#include <string_view>

namespace richnet::storage_detail {
void execute(sqlite3* db, const char* sql);
class Statement {
public:
    Statement(sqlite3* db, const char* sql);
    ~Statement();
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    void bind(int index, const nlohmann::json& value);
    bool row();
    nlohmann::json record() const;
    std::string text(int column) const;
    std::int64_t integer(int column) const;
private:
    sqlite3_stmt* statement_{};
};
// 析构时回滚尚未提交的事务；成功路径须显式 commit()。
class Transaction {
public:
    explicit Transaction(sqlite3* db, bool write = true);
    ~Transaction();
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    void commit();
private:
    sqlite3* db_;
    bool committed_{};
};
void require_keys(const nlohmann::json& value, std::initializer_list<std::string_view> keys);
void validate_role(const nlohmann::json& role, ClientProfile profile);
nlohmann::json default_settings();
void validate_settings(const nlohmann::json& settings, ClientProfile profile);
}
