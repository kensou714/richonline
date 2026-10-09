#include "storage_detail.hpp"
#include "credentials.hpp"
#include <algorithm>
#include <array>
#include <cmath>

namespace richnet {
using namespace storage_detail;
namespace {
constexpr std::array<const char*,13> fields={"name","model","level","experience","coins","gold","bank",
                                           "wins","losses","draws","vip_level","escapes","purchase_score"};
std::int64_t integer(const nlohmann::json& value,std::int64_t maximum) {
    if (!value.is_number_integer() || value<nlohmann::json(0) || value>nlohmann::json(maximum))
        throw StorageError("role_integer_out_of_range");
    return value.get<std::int64_t>();
}
void audit(sqlite3* db,const nlohmann::json& role,const nlohmann::json& change,const std::string& reason,
           const std::string& source = "native-admin") {
    Statement insert(db,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,?,?,'')");
    insert.bind(1,role.at("role_id")); insert.bind(2,role.at("username"));
    insert.bind(3,change.at("field")); insert.bind(4,change.at("old").dump());
    insert.bind(5,change.at("new").dump()); insert.bind(6,source); insert.bind(7,reason); insert.row();
}
}
namespace storage_detail {
void validate_role(const nlohmann::json& role, ClientProfile profile) {
    if (!role.at("name").is_string() || client_text(role.at("name").get<std::string>(),profile).size()>=32)
        throw StorageError("role_name_invalid");
    integer(role.at("model"),profile==ClientProfile::richonline?8:4);
    integer(role.at("level"),20); integer(role.at("vip_level"),3);
    for (const auto* field:{"experience","wins","losses","draws","escapes","purchase_score"})
        integer(role.at(field),2147483647);
    for (const auto* field:{"coins","gold","bank"}) {
        const auto& value=role.at(field);
        if (!value.is_number() || !std::isfinite(value.get<double>()) || value.get<double>()<0)
            throw StorageError("role_balance_out_of_range");
    }
}
}

nlohmann::json Storage::list_accounts(const nlohmann::json& payload) {
    require_keys(payload,{"offset","limit"});
    const auto offset=integer(payload.value("offset",nlohmann::json(0)),2147483647);
    const auto limit=integer(payload.value("limit",nlohmann::json(100)),1000);
    if (limit==0) throw StorageError("list_limit_invalid");
    Transaction transaction(db_,false);
    Statement count(db_,"SELECT count(*) FROM roles"); count.row();
    Statement select(db_,"SELECT * FROM roles ORDER BY role_id LIMIT ? OFFSET ?");
    select.bind(1,limit); select.bind(2,offset);
    auto accounts=nlohmann::json::array();
    while (select.row()) accounts.push_back(select.record());
    transaction.commit();
    return {{"accounts",accounts},{"total",count.integer(0)}};
}

nlohmann::json Storage::create_account(const nlohmann::json& payload) {
    require_keys(payload,{"username","password"});
    const auto username=payload.at("username").get<std::string>();
    if (client_text(username,profile_).size()>=32) throw StorageError("username_invalid");
    const auto password=client_text(payload.at("password").get<std::string>(),profile_);
    if (password.size()>=64) throw StorageError("password_length_invalid");
    const auto verifier=create_verifier(password);
    Transaction transaction(db_);
    Statement exists(db_,"SELECT 1 FROM accounts WHERE username=?"); exists.bind(1,username);
    if (exists.row()) throw StorageError("account_exists");
    const auto result=create_account_with_verifier(username,verifier,"native-admin");
    transaction.commit();
    return result;
}

nlohmann::json Storage::create_account_with_verifier(const std::string& username,
    const CredentialVerifier& verifier,const std::string& source) {
    Statement next(db_,"SELECT value,(SELECT coalesce(max(role_id),0)+1 FROM roles) FROM metadata WHERE key='next_role_id'");
    if (!next.row()) throw StorageError("next_role_id_missing");
    const auto role_id=std::max(next.integer(0),next.integer(1));
    if (role_id<1 || role_id>=2147483647) throw StorageError("role_id_exhausted");
    const auto defaults=get_config().at("settings").at("default_role");
    nlohmann::json role={{"role_id",role_id},{"username",username},{"name",username},
        {"model",defaults.at("model")},{"level",defaults.at("level")},{"experience",defaults.at("experience")},
        {"coins",defaults.at("mpoints")},{"gold",defaults.at("gold")},{"bank",defaults.at("bank")},
        {"vip_level",defaults.at("vip_level")},{"wins",0},{"losses",0},{"draws",0},{"escapes",0},{"purchase_score",0}};
    validate_role(role,profile_);
    Statement account(db_,"INSERT INTO accounts(username,salt,password_hash) VALUES(?,?,?)");
    account.bind(1,username); account.bind(2,verifier.salt); account.bind(3,verifier.password_hash); account.row();
    Statement insert(db_,"INSERT INTO roles(role_id,username,name,model,level,experience,coins,gold,bank,wins,losses,draws,vip_level,escapes,purchase_score) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    insert.bind(1,role_id); insert.bind(2,username);
    for (std::size_t i=0;i<fields.size();++i) insert.bind(static_cast<int>(i)+3,role.at(fields[i]));
    insert.row();
    Statement advance(db_,"UPDATE metadata SET value=? WHERE key='next_role_id'");
    advance.bind(1,std::to_string(role_id+1)); advance.row();
    audit(db_,role,{{"field","account_created"},{"old",nullptr},{"new",role}},
        source=="login" ? "first login account registration" : "administrator account creation",source);
    return {{"account",role}};
}

nlohmann::json Storage::update_account(const nlohmann::json& payload) {
    require_keys(payload,{"role_id","expected","changes","reason"});
    const auto role_id=integer(payload.at("role_id"),2147483647);
    const auto reason=payload.at("reason").get<std::string>();
    if (reason.empty() || reason.size()>1024 || reason.find('\0')!=std::string::npos)
        throw StorageError("audit_reason_invalid");
    const auto& changes=payload.at("changes");
    const auto& expected=payload.at("expected");
    if (!changes.is_object() || changes.empty() || !expected.is_object()) throw StorageError("role_changes_invalid");
    Transaction transaction(db_);
    Statement select(db_,"SELECT * FROM roles WHERE role_id=?"); select.bind(1,role_id);
    if (!select.row()) throw StorageError("role_not_found");
    const auto current=select.record();
    auto updated=current;
    for (const auto& [field,value]:changes.items()) {
        if (std::find(fields.begin(),fields.end(),field)==fields.end()) throw StorageError("role_field_not_editable");
        if (!expected.contains(field) || expected.at(field)!=current.at(field))
            throw StorageError("role_changed_refresh_required");
        updated[field]=value;
    }
    for (const auto& [field,value]:expected.items()) {
        if (!current.contains(field)) throw StorageError("expected_field_unknown");
        if (current.at(field)!=value) throw StorageError("role_changed_refresh_required");
    }
    validate_role(updated,profile_);
    Statement write(db_,"UPDATE roles SET name=?,model=?,level=?,experience=?,coins=?,gold=?,bank=?,wins=?,losses=?,draws=?,vip_level=?,escapes=?,purchase_score=? WHERE role_id=?");
    for (std::size_t i=0;i<fields.size();++i) write.bind(static_cast<int>(i)+1,updated.at(fields[i]));
    write.bind(14,role_id); write.row();
    for (const auto& [field,value]:changes.items())
        if (current.at(field)!=value) audit(db_,current,{{"field",field},{"old",current.at(field)},{"new",value}},reason);
    transaction.commit();
    return {{"account",updated}};
}

bool Storage::verify_credentials(const std::string& username,std::span<const std::uint8_t> password) {
    const std::lock_guard lock(mutex_);
    if (password.empty() || password.size()>=64 || std::find(password.begin(),password.end(),0)!=password.end())
        return false;
    Statement select(db_,"SELECT salt,password_hash FROM accounts WHERE username=?"); select.bind(1,username);
    if (!select.row()) return false;
    return verify_password(password,{select.text(0),select.text(1)});
}

LoginOutcome Storage::login(const std::string& username,std::span<const std::uint8_t> password) {
    const std::lock_guard lock(mutex_);
    if (password.empty() || password.size()>=64 || std::find(password.begin(),password.end(),0)!=password.end())
        return LoginOutcome::invalid_credentials;
    try {
        if (client_text(username,profile_).size()>=32) return LoginOutcome::invalid_credentials;
    } catch (const std::runtime_error&) { return LoginOutcome::invalid_credentials; }
    Transaction transaction(db_);
    {
        Statement select(db_,"SELECT salt,password_hash FROM accounts WHERE username=?"); select.bind(1,username);
        if (select.row()) {
            const auto outcome=verify_password(password,{select.text(0),select.text(1)})
                ? LoginOutcome::authenticated : LoginOutcome::password_mismatch;
            transaction.commit();
            return outcome;
        }
    }
    if (!get_config().at("settings").at("registration_enabled").get<bool>())
        return LoginOutcome::registration_disabled;
    static_cast<void>(create_account_with_verifier(username,create_verifier(password),"login"));
    transaction.commit();
    return LoginOutcome::registered;
}

nlohmann::json Storage::roles_for_username(const std::string& username) {
    const std::lock_guard lock(mutex_);
    Statement select(db_,"SELECT * FROM roles WHERE username=? ORDER BY role_id");
    select.bind(1,username);
    auto roles=nlohmann::json::array();
    while (select.row()) roles.push_back(select.record());
    return roles;
}
}
