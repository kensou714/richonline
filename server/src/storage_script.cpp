#include "storage.hpp"
#include <sqlite3.h>
#include <cmath>
#include <limits>
#include <memory>

namespace richnet {
nlohmann::json Storage::script_batch(const nlohmann::json& request) {
    using Json = nlohmann::json;
    const auto& statements = request.at("statements");
    if (!statements.is_array() || statements.empty() || statements.size() > 64)
        throw StorageError("lua_db_statements_invalid");
    std::lock_guard guard(mutex_);
    const auto execute = [&](const char* sql) {
        if (sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) != SQLITE_OK) throw StorageError("lua_db_transaction_failed");
    };
    const auto authorizer = [](void*, int action, const char*, const char*, const char*, const char*) {
        switch (action) {
        case SQLITE_TRANSACTION: case SQLITE_SAVEPOINT: case SQLITE_ATTACH: case SQLITE_DETACH: case SQLITE_PRAGMA:
            return SQLITE_DENY;
        default: return SQLITE_OK;
        }
    };
    execute("BEGIN IMMEDIATE");
    sqlite3_set_authorizer(db_, authorizer, nullptr);
    int remaining_steps=2000;
    sqlite3_progress_handler(db_,1000,[](void* value) {
        return --*static_cast<int*>(value)<=0 ? 1 : 0;
    },&remaining_steps);
    try {
        auto results = Json::array(); std::size_t rows_total = 0, bytes_total = 0;
        for (const auto& command : statements) {
            const auto sql = command.at("sql").get<std::string>();
            if (sql.empty() || sql.size() > 65536 || sql.find('\0') != sql.npos) throw StorageError("lua_db_sql_invalid");
            sqlite3_stmt* raw = nullptr; const char* tail = nullptr;
            const auto prepared = sqlite3_prepare_v2(db_, sql.c_str(), static_cast<int>(sql.size()), &raw, &tail);
            const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw, sqlite3_finalize);
            if (prepared != SQLITE_OK || !raw) throw StorageError("lua_db_prepare_failed");
            for (; tail < sql.data() + sql.size(); ++tail)
                if (*tail != ' ' && *tail != '\t' && *tail != '\r' && *tail != '\n') throw StorageError("lua_db_multiple_statements");
            const auto parameters = command.value("params", Json::array());
            if (!parameters.is_array() || parameters.size() != static_cast<std::size_t>(sqlite3_bind_parameter_count(raw)))
                throw StorageError("lua_db_parameters_invalid");
            int index = 0;
            for (const auto& parameter : parameters) {
                ++index; int code = SQLITE_MISUSE;
                if (parameter.is_null()) code = sqlite3_bind_null(raw, index);
                else if (parameter.is_boolean()) code = sqlite3_bind_int(raw, index, parameter.get<bool>() ? 1 : 0);
                else if (parameter.is_number_integer()) {
                    if (parameter.is_number_unsigned() && parameter.get<std::uint64_t>() > static_cast<std::uint64_t>(std::numeric_limits<sqlite3_int64>::max()))
                        throw StorageError("lua_db_integer_overflow");
                    code = sqlite3_bind_int64(raw, index, parameter.get<sqlite3_int64>());
                } else if (parameter.is_number_float() && std::isfinite(parameter.get<double>()))
                    code = sqlite3_bind_double(raw, index, parameter.get<double>());
                else if (parameter.is_string()) {
                    const auto& text = parameter.get_ref<const std::string&>();
                    if (text.size() > 1024U * 1024U) throw StorageError("lua_db_parameter_too_large");
                    code = sqlite3_bind_text(raw, index, text.data(), static_cast<int>(text.size()), SQLITE_TRANSIENT);
                }
                if (code != SQLITE_OK) throw StorageError("lua_db_bind_failed");
            }
            auto rows = Json::array(); int step = SQLITE_OK;
            while ((step = sqlite3_step(raw)) == SQLITE_ROW) {
                if (++rows_total > 4096) throw StorageError("lua_db_result_limit_exceeded");
                auto row = Json::object();
                for (int column = 0; column < sqlite3_column_count(raw); ++column) {
                    const std::string key = sqlite3_column_name(raw, column);
                    if (row.contains(key)) throw StorageError("lua_db_duplicate_column_name");
                    switch (sqlite3_column_type(raw, column)) {
                    case SQLITE_NULL: row[key] = nullptr; break;
                    case SQLITE_INTEGER: row[key] = sqlite3_column_int64(raw, column); break;
                    case SQLITE_FLOAT: row[key] = sqlite3_column_double(raw, column); break;
                    default: {
                        const auto size = static_cast<std::size_t>(sqlite3_column_bytes(raw, column)); bytes_total += size;
                        if (bytes_total > 4U * 1024U * 1024U) throw StorageError("lua_db_result_limit_exceeded");
                        const auto* data = static_cast<const char*>(sqlite3_column_blob(raw, column));
                        row[key] = size ? std::string(data, size) : std::string{}; break;
                    }
                    }
                }
                rows.push_back(std::move(row));
            }
            if (step != SQLITE_DONE) throw StorageError("lua_db_step_failed");
            const auto changes = sqlite3_stmt_readonly(raw) ? 0 : sqlite3_changes(db_);
            if (command.contains("expect_changes") && command.at("expect_changes") != changes)
                throw StorageError("lua_db_expected_changes_mismatch");
            results.push_back({{"rows", std::move(rows)}, {"changes", changes}, {"last_insert_id", sqlite3_last_insert_rowid(db_)}});
        }
        sqlite3_progress_handler(db_,0,nullptr,nullptr);
        sqlite3_set_authorizer(db_, nullptr, nullptr); execute("COMMIT"); return results;
    } catch (...) {
        sqlite3_progress_handler(db_,0,nullptr,nullptr);
        sqlite3_set_authorizer(db_, nullptr, nullptr); sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); throw;
    }
}
}
