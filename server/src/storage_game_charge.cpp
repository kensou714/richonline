#include "storage_detail.hpp"
#include <cmath>

namespace richnet {
using namespace storage_detail;
namespace {
constexpr const char* source="native-game-charge";
void validate_text(const std::string& text,std::size_t limit,const char* error) {
    if(text.empty() || text.size()>limit || text.find('\0')!=std::string::npos)
        throw StorageError(error);
}
}

GameAccount Storage::game_account_for_role(std::int64_t role_id) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline)throw StorageError("game_charge_profile_invalid");
    Statement account(db_,"SELECT username,gold FROM roles WHERE role_id=?");account.bind(1,role_id);
    if(!account.row())throw StorageError("game_charge_role_missing");
    const auto record=account.record();const auto gold=record.at("gold").get<double>();
    if(!std::isfinite(gold) || gold<0)throw StorageError("game_charge_balance_invalid");
    return {record.at("username").get<std::string>(),gold};
}

GameGoldChargeResult Storage::consume_game_gold(const std::string& username,std::int64_t role_id,
                                               const GameGoldCharge& charge) {
    const std::lock_guard lock(mutex_);
    if(profile_!=ClientProfile::richonline) throw StorageError("game_charge_profile_invalid");
    validate_text(charge.operation_id,256,"game_charge_operation_id_invalid");
    validate_text(charge.reason,1024,"game_charge_reason_invalid");
    Transaction transaction(db_);
    Statement owner(db_,"SELECT gold FROM roles WHERE username=? AND role_id=?");
    owner.bind(1,username);owner.bind(2,role_id);
    if(!owner.row()) throw StorageError("game_charge_role_not_owned");
    const auto gold=owner.record().at("gold").get<double>();
    if(!std::isfinite(gold) || gold<0) throw StorageError("game_charge_balance_invalid");
    if(!std::isfinite(charge.amount) || charge.amount<=0)
        return {GameChargeStatus::invalid_amount,false,std::nullopt};
    const nlohmann::json request{{"username",username},{"role_id",role_id},
        {"amount",charge.amount},{"reason",charge.reason}};
    Statement prior(db_,"SELECT role_id,source,request,result FROM operations WHERE operation_id=?");
    prior.bind(1,charge.operation_id);
    if(prior.row()) {
        if(prior.integer(0)!=role_id || prior.text(1)!=source || prior.text(2)!=request.dump())
            throw StorageError("game_charge_operation_conflict");
        try {
            const auto result=nlohmann::json::parse(prior.text(3));
            const auto code=result.at("status").get<std::string>();
            const auto balance=result.at("gold_after").get<double>();
            if(!std::isfinite(balance) || balance<0 ||
                (code!="success" && code!="insufficient_funds" && code!="invalid_amount"))
                throw StorageError("game_charge_result_invalid");
            transaction.commit();
            return {code=="success" ? GameChargeStatus::success :
                code=="insufficient_funds" ? GameChargeStatus::insufficient_funds : GameChargeStatus::invalid_amount,
                true,balance};
        } catch(const nlohmann::json::exception&) {throw StorageError("game_charge_result_invalid");}
    }
    auto status=GameChargeStatus::success;
    double next=gold;
    if(charge.amount>gold) status=GameChargeStatus::insufficient_funds;
    else {
        next=gold-charge.amount;
        if(!std::isfinite(next) || gold-next!=charge.amount) {
            status=GameChargeStatus::invalid_amount;next=gold;
        }
    }
    if(status==GameChargeStatus::success) {
        Statement update(db_,"UPDATE roles SET gold=? WHERE username=? AND role_id=?");
        update.bind(1,next);update.bind(2,username);update.bind(3,role_id);update.row();
        Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,'gold',?,?,?,?,?)");
        audit.bind(1,role_id);audit.bind(2,username);audit.bind(3,nlohmann::json(gold).dump());
        audit.bind(4,nlohmann::json(next).dump());audit.bind(5,source);audit.bind(6,charge.reason);
        audit.bind(7,charge.operation_id);audit.row();
    }
    const auto code=status==GameChargeStatus::success ? "success" :
        status==GameChargeStatus::insufficient_funds ? "insufficient_funds" : "invalid_amount";
    const nlohmann::json result{{"status",code},{"gold_after",next}};
    Statement operation(db_,"INSERT INTO operations(operation_id,role_id,source,reason,request,result) VALUES(?,?,?,?,?,?)");
    operation.bind(1,charge.operation_id);operation.bind(2,role_id);operation.bind(3,source);
    operation.bind(4,charge.reason);operation.bind(5,request.dump());operation.bind(6,result.dump());operation.row();
    transaction.commit();
    return {status,false,next};
}
}
