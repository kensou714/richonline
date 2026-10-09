#include "storage_detail.hpp"
#include <algorithm>
#include <limits>

namespace richnet::storage_detail {
void execute(sqlite3* db,const char* sql) {
    if (sqlite3_exec(db,sql,nullptr,nullptr,nullptr)!=SQLITE_OK) throw StorageError("database_sql_failed");
}
Statement::Statement(sqlite3* db,const char* sql) {
    if (sqlite3_prepare_v2(db,sql,-1,&statement_,nullptr)!=SQLITE_OK)
        throw StorageError("database_prepare_failed");
}
Statement::~Statement() { sqlite3_finalize(statement_); }
void Statement::bind(int index,const nlohmann::json& value) {
    int result=SQLITE_MISMATCH;
    if (value.is_string()) {
        const auto text=value.get<std::string>();
        result=sqlite3_bind_text(statement_,index,text.c_str(),static_cast<int>(text.size()),SQLITE_TRANSIENT);
    } else if (value.is_number_unsigned()) {
        const auto number=value.get<std::uint64_t>();
        if (number>static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            throw StorageError("request_integer_out_of_range");
        result=sqlite3_bind_int64(statement_,index,static_cast<std::int64_t>(number));
    } else if (value.is_number_integer()) result=sqlite3_bind_int64(statement_,index,value.get<std::int64_t>());
    else if (value.is_number_float()) result=sqlite3_bind_double(statement_,index,value.get<double>());
    else if (value.is_null()) result=sqlite3_bind_null(statement_,index);
    if (result!=SQLITE_OK) throw StorageError("database_bind_failed");
}
bool Statement::row() {
    const int result=sqlite3_step(statement_);
    if (result==SQLITE_ROW) return true;
    if (result==SQLITE_DONE) return false;
    if (result==SQLITE_CONSTRAINT) throw StorageError("database_constraint_failed");
    if (result==SQLITE_BUSY || result==SQLITE_LOCKED) throw StorageError("database_busy");
    throw StorageError("database_step_failed");
}
nlohmann::json Statement::record() const {
    auto result=nlohmann::json::object();
    for (int column=0; column<sqlite3_column_count(statement_); ++column) {
        const auto name=sqlite3_column_name(statement_,column);
        switch (sqlite3_column_type(statement_,column)) {
        case SQLITE_INTEGER: result[name]=integer(column); break;
        case SQLITE_FLOAT: result[name]=sqlite3_column_double(statement_,column); break;
        case SQLITE_TEXT: result[name]=text(column); break;
        case SQLITE_NULL: result[name]=nullptr; break;
        default: throw StorageError("database_column_type_unsupported");
        }
    }
    return result;
}
std::string Statement::text(int column) const {
    const auto* bytes=sqlite3_column_text(statement_,column);
    if (!bytes) throw StorageError("database_text_null");
    return {reinterpret_cast<const char*>(bytes),static_cast<std::size_t>(sqlite3_column_bytes(statement_,column))};
}
std::int64_t Statement::integer(int column) const { return sqlite3_column_int64(statement_,column); }
Transaction::Transaction(sqlite3* db,bool write):db_(db) { execute(db_,write?"BEGIN IMMEDIATE":"BEGIN"); }
Transaction::~Transaction() { if (!committed_) sqlite3_exec(db_,"ROLLBACK",nullptr,nullptr,nullptr); }
void Transaction::commit() { execute(db_,"COMMIT"); committed_=true; }
void require_keys(const nlohmann::json& value,std::initializer_list<std::string_view> keys) {
    if (!value.is_object()) throw StorageError("request_object_required");
    for (const auto& [key,unused]:value.items()) {
        (void)unused;
        if (std::find(keys.begin(),keys.end(),key)==keys.end()) throw StorageError("request_unknown_field");
    }
}
}
