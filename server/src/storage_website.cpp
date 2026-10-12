#include "storage_detail.hpp"
#include <algorithm>
#include <cmath>

namespace richnet {
using namespace storage_detail;
namespace {
void new_password(const std::string& value) {
    if (value.size()<8 || value.size()>32 ||
        value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?/|")!=std::string::npos)
        throw StorageError("website_password_format");
}
void write_audit(sqlite3* db,const nlohmann::json& role,const std::string& field,
    const nlohmann::json& before,const nlohmann::json& after,const std::string& operation) {
    Statement row(db,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,'website',?,?)");
    row.bind(1,role.at("role_id")); row.bind(2,role.at("username")); row.bind(3,field);
    row.bind(4,before.dump()); row.bind(5,after.dump());
    row.bind(6,field=="coins"?"self-service 10000 M-points grant":"owner password change");
    row.bind(7,operation); row.row();
}
}

// 仅由本机受信任管理管道调用。公共网站固定映射到这四个命令，不暴露通用控制接口。
// dispatch 持有数据库互斥锁；认证、余额条件、发放与审计在同一事务中完成。
nlohmann::json Storage::website_account(const std::string& command,const nlohmann::json& payload) {
    if(command=="website.register") {
        require_keys(payload,{"username","password"});
        const auto name=payload.at("username").get<std::string>();
        if(name.size()<4 || name.size()>20 ||
            name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")!=std::string::npos)
            throw StorageError("website_username_format");
        const auto password=payload.at("password").get<std::string>(); new_password(password);
        Transaction tx(db_);
        if(!get_config().at("settings").at("registration_enabled").get<bool>())
            throw StorageError("website_registration_closed");
        Statement exists(db_,"SELECT 1 FROM accounts WHERE username=?"); exists.bind(1,name);
        if(exists.row()) throw StorageError("account_exists");
        const auto result=create_account_with_verifier(name,create_verifier(client_text(password,profile_)),"website");
        tx.commit(); return {{"username",name},{"roleId",result.at("account").at("role_id")}};
    }
    if(command=="website.password") require_keys(payload,{"username","password","newPassword"});
    else if(command=="website.claim") require_keys(payload,{"username","password","roleId","operationId"});
    else require_keys(payload,{"username","password"});
    const auto username=payload.at("username").get<std::string>();
    const auto password=client_text(payload.at("password").get<std::string>(),profile_);
    if(username.empty() || username.size()>128 || password.empty() || password.size()>=64)
        throw StorageError("website_credentials_invalid");
    Transaction tx(db_);
    Statement credentials(db_,"SELECT salt,password_hash FROM accounts WHERE username=?");
    credentials.bind(1,username);
    if(!credentials.row() || !verify_password(password,{credentials.text(0),credentials.text(1)}))
        throw StorageError("website_credentials_invalid");
    Statement list(db_,"SELECT role_id,username,name,coins,gold FROM roles WHERE username=? ORDER BY role_id");
    list.bind(1,username); auto roles=nlohmann::json::array();
    while(list.row()) roles.push_back(list.record());
    if(roles.empty()) throw StorageError("website_role_missing");
    if(command=="website.account") {
        tx.commit(); return {{"roles",roles}};
    }
    if(command=="website.password") {
        const auto next=payload.at("newPassword").get<std::string>(); new_password(next);
        const auto verifier=create_verifier(client_text(next,profile_));
        Statement update(db_,"UPDATE accounts SET salt=?,password_hash=? WHERE username=?");
        update.bind(1,verifier.salt); update.bind(2,verifier.password_hash); update.bind(3,username); update.row();
        // 审计只记录发生了变更，不记录密码、盐或密码散列。
        write_audit(db_,roles.front(),"password_changed",nullptr,true,"");
        tx.commit(); return {{"changed",true}};
    }
    const auto operation=payload.at("operationId").get<std::string>();
    if(operation.size()!=32 || operation.find_first_not_of("0123456789abcdef")!=std::string::npos)
        throw StorageError("website_operation_invalid");
    if(!payload.at("roleId").is_number_integer()) throw StorageError("website_role_invalid");
    const auto role_id=payload.at("roleId").get<std::int64_t>();
    const auto selected=std::find_if(roles.begin(),roles.end(),[&](const auto& role){return role.at("role_id")==role_id;});
    if(selected==roles.end()) throw StorageError("website_role_invalid");
    // 同一次点击在网络失败后重试仍返回原结果，永不重复发放。
    Statement receipt(db_,"SELECT role_id,new_value FROM audit WHERE username=? AND operation_id=? AND source='website' AND field='coins' LIMIT 1");
    receipt.bind(1,username); receipt.bind(2,operation);
    if(receipt.row()) {
        if(receipt.integer(0)!=role_id) throw StorageError("website_operation_invalid");
        const auto after=nlohmann::json::parse(receipt.text(1));
        tx.commit(); return {{"granted",10000},{"balance",after},{"replayed",true}};
    }
    const auto before=selected->at("coins").get<double>();
    if(!std::isfinite(before) || before<0) throw StorageError("website_balance_invalid");
    if(before>=10000) throw StorageError("website_balance_limit");
    const auto after=before+10000;
    Statement update(db_,"UPDATE roles SET coins=? WHERE username=? AND role_id=?");
    update.bind(1,after); update.bind(2,username); update.bind(3,role_id); update.row();
    write_audit(db_,*selected,"coins",before,after,operation);
    tx.commit(); return {{"granted",10000},{"balance",after},{"replayed",false}};
}
}
