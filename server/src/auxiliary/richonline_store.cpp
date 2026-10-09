#include "richonline_auxiliary_store.hpp"
#include "storage_detail.hpp"

#include <algorithm>
#include <limits>

namespace richnet {
using namespace storage_detail;
namespace {
Bytes validate_text(const std::string& text) {
    const auto bytes = text.empty() ? Bytes{} : client_text(text, ClientProfile::richonline);
    // The wire encoder also verifies the vulnerable client display loop bounds.
    static_cast<void>(encode_richonline_intro(RichonlineAuxiliaryName{}, bytes));
    return bytes;
}
View unpadded(const RichonlineAuxiliaryName& name) {
    const auto end = std::find(name.begin(), name.end(), 0);
    return View(name).first(static_cast<std::size_t>(end - name.begin()));
}
RichonlineIntroSnapshot read_intro(sqlite3* db, std::int64_t role_id) {
    Statement query(db, "SELECT text_utf8,revision FROM role_introductions WHERE role_id=?");
    query.bind(1, role_id);
    if (query.row()) return {role_id, query.text(0), query.integer(1)};
    // The declared default for a known role is an unedited, empty introduction.
    // Revision zero denotes that persisted role's lack of an introduction row.
    return {role_id, {}, 0};
}
}

RichonlineAuxiliaryStore::RichonlineAuxiliaryStore(const std::filesystem::path& database) {
    const auto path = database.u8string();
    const auto opened = sqlite3_open_v2(reinterpret_cast<const char*>(path.c_str()), &db_,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);
    try {
        if (opened != SQLITE_OK) throw StorageError("auxiliary_database_open_failed");
        if (sqlite3_busy_timeout(db_, 5000) != SQLITE_OK) throw StorageError("auxiliary_database_timeout_failed");
        execute(db_, "PRAGMA foreign_keys=ON");
        Transaction transaction(db_);
        Statement profile(db_, "SELECT value FROM metadata WHERE key='client_profile'");
        if (!profile.row() || profile.text(0) != client_profile_name(ClientProfile::richonline))
            throw StorageError("auxiliary_database_profile_mismatch");
        execute(db_, R"sql(
CREATE TABLE IF NOT EXISTS role_introductions(
 role_id INTEGER PRIMARY KEY REFERENCES roles(role_id),
 text_utf8 TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0)) STRICT;
)sql");
        transaction.commit();
    } catch (...) {
        sqlite3_close(db_); db_ = nullptr;
        throw;
    }
}

RichonlineAuxiliaryStore::~RichonlineAuxiliaryStore() { sqlite3_close(db_); }

RichonlineIntroSnapshot RichonlineAuxiliaryStore::introduction(const RichonlineAuxiliaryName& name) {
    const auto requested = unpadded(name);
    if (requested.empty()) throw StorageError("intro_role_name_empty");
    const std::lock_guard lock(mutex_);
    Transaction transaction(db_, false);
    // Match wire bytes against canonical account-role text. No permissive ANSI
    // conversion is used to turn an invalid request into another player's name.
    Statement roles(db_, "SELECT role_id,name FROM roles ORDER BY role_id");
    std::optional<std::int64_t> matched;
    while (roles.row()) {
        const auto wire_name = client_text(roles.text(1), ClientProfile::richonline);
        if (!std::ranges::equal(wire_name, requested)) continue;
        if (matched) throw StorageError("intro_role_name_ambiguous");
        matched = roles.integer(0);
    }
    if (!matched) throw StorageError("intro_role_not_found");
    auto result = read_intro(db_, *matched);
    static_cast<void>(validate_text(result.text_utf8));
    transaction.commit();
    return result;
}

std::optional<Bytes> RichonlineAuxiliaryStore::intro_response(View request) {
    const auto name = decode_richonline_intro_request(request);
    if (!name) return std::nullopt;
    const auto data = introduction(*name);
    return encode_richonline_intro(*name, validate_text(data.text_utf8));
}

RichonlineIntroSnapshot RichonlineAuxiliaryStore::save_introduction(const std::string& authenticated_username,
    std::int64_t role_id, const std::string& text_utf8, std::int64_t expected_revision,
    const std::string& audit_reason) {
    static_cast<void>(validate_text(text_utf8));
    if (expected_revision < 0 || expected_revision == std::numeric_limits<std::int64_t>::max())
        throw StorageError("intro_revision_invalid");
    if (audit_reason.empty() || audit_reason.size() > 1024 || audit_reason.find('\0') != std::string::npos)
        throw StorageError("intro_audit_reason_invalid");
    const std::lock_guard lock(mutex_);
    Transaction transaction(db_);
    Statement role(db_, "SELECT username FROM roles WHERE role_id=?");
    role.bind(1, role_id);
    if (!role.row() || role.text(0) != authenticated_username) throw StorageError("intro_role_not_owned");
    auto current = read_intro(db_, role_id);
    if (current.revision != expected_revision) throw StorageError("intro_changed_refresh_required");
    if (current.text_utf8 != text_utf8) {
        Statement update(db_, "INSERT INTO role_introductions(role_id,text_utf8,revision) VALUES(?,?,?) "
            "ON CONFLICT(role_id) DO UPDATE SET text_utf8=excluded.text_utf8,revision=excluded.revision");
        update.bind(1, role_id); update.bind(2, text_utf8); update.bind(3, current.revision + 1); update.row();
        Statement audit(db_, "INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) "
            "VALUES(?,?,'introduction',?,?,'native-auxiliary',?,'')");
        audit.bind(1, role_id); audit.bind(2, authenticated_username); audit.bind(3, current.text_utf8);
        audit.bind(4, text_utf8); audit.bind(5, audit_reason); audit.row();
        current = {role_id, text_utf8, current.revision + 1};
    }
    transaction.commit();
    return current;
}
}
