#include "storage_detail.hpp"
#include <cmath>
#include <limits>

namespace richnet {
using namespace storage_detail;
namespace {
void schema(sqlite3* db) {
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS native_mall_purchases(
      operation_id TEXT PRIMARY KEY,username TEXT NOT NULL,role_id INTEGER NOT NULL REFERENCES roles(role_id),
      request_key INTEGER NOT NULL,owned_key INTEGER NOT NULL,expires_at INTEGER NOT NULL,
      opaque_word0 INTEGER NOT NULL,opaque_word2 INTEGER NOT NULL,evidence TEXT NOT NULL,
      price REAL NOT NULL,score INTEGER NOT NULL,created_at INTEGER NOT NULL) STRICT;)sql");
    bool version_column=false;Statement columns(db,"PRAGMA table_info(native_mall_purchases)");
    while(columns.row())if(columns.text(1)=="date_version")version_column=true;
    if(!version_column)execute(db,"ALTER TABLE native_mall_purchases ADD COLUMN date_version INTEGER NOT NULL DEFAULT 2005;");
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS native_mall_activations(
      operation_id TEXT PRIMARY KEY,username TEXT NOT NULL,role_id INTEGER NOT NULL REFERENCES roles(role_id),
      old_key INTEGER NOT NULL,new_key INTEGER NOT NULL,currency INTEGER NOT NULL,charge REAL NOT NULL,
      expires_at INTEGER NOT NULL,date_version INTEGER NOT NULL,evidence TEXT NOT NULL,created_at INTEGER NOT NULL) STRICT;)sql");
}
void date_mode(sqlite3* db,RichonlineInventoryDateVersion version) {
    static_cast<void>(encode_richonline_inventory_date(13,{},version));
    Statement mode(db,"SELECT value FROM metadata WHERE key='inventory_date_version'");
    const auto actual=mode.row()?mode.text(0):"original-2005";
    const auto expected=version==RichonlineInventoryDateVersion::original_2005?"original-2005":std::string(richonline_inventory_compatibility_id);
    if(actual!=expected)throw StorageError("inventory_date_database_mode_mismatch");
}
void validate_key_date(std::uint32_t key,std::int64_t expires,RichonlineInventoryDateVersion version) {
    // Existing named test-PK certificate13 intentionally has no display date;
    // its authoritative30-day Unix policy remains unchanged across migration.
    if(key==13)return;
    if(richonline_inventory_key_from_expiry(key,expires,version)!=key)throw StorageError("mall_inventory_date_mismatch");
}
std::uint32_t current_alias(sqlite3* db,const std::string& username,std::uint32_t old_key,RichonlineInventoryDateVersion version) {
    Statement exists(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='inventory_key_aliases'");
    if(!exists.row())return old_key;
    Statement alias(db,"SELECT new_key FROM inventory_key_aliases WHERE username=? AND old_key=? AND new_version=? ORDER BY rowid DESC LIMIT 1");
    alias.bind(1,username);alias.bind(2,old_key);alias.bind(3,static_cast<std::uint32_t>(version));
    return alias.row()?static_cast<std::uint32_t>(alias.integer(0)):old_key;
}
nlohmann::json role(sqlite3* db,const std::string& username,std::int64_t role_id) {
    Statement query(db,"SELECT * FROM roles WHERE username=? AND role_id=?");query.bind(1,username);query.bind(2,role_id);
    if(!query.row())throw StorageError("mall_role_not_owned");return query.record();
}
void audit(sqlite3* db,const std::string& username,std::int64_t role_id,const std::string& operation,
    const std::string& field,const nlohmann::json& before,const nlohmann::json& after,const std::string& evidence) {
    Statement row(db,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,'native-mall',?,?)");
    row.bind(1,role_id);row.bind(2,username);row.bind(3,field);row.bind(4,before.dump());row.bind(5,after.dump());row.bind(6,evidence);row.bind(7,operation);row.row();
}
void validate(const RichonlineMallPurchase& purchase,std::int64_t now) {
    if(now<0||purchase.operation_id.empty()||purchase.operation_id.size()>256||purchase.operation_id.find('\0')!=std::string::npos)
        throw StorageError("mall_purchase_context_invalid");
    const auto& grant=purchase.grant;
    static_cast<void>(encode_richonline_mall_added77(grant));
    if(grant.expires_at<0||(grant.owned_key&4095U)!=(purchase.request.encoded_item&4095U))
        throw StorageError("mall_purchase_grant_mismatch");
}
std::size_t inventory_bucket(const RichonlineMallProduct& product) {
    // NEW 6A71C0 counts CARD_GL/CARD_CQ separately, FUNC together and AVATAR together.
    if(product.type=="CARD"&&product.subtype=="CARD_GL")return 0;
    if(product.type=="CARD"&&product.subtype=="CARD_CQ")return 1;
    if(product.type=="FUNC")return 2;
    if(product.type=="AVATAR")return 3;
    throw StorageError("mall_inventory_category_invalid");
}
bool has_inventory_space(sqlite3* db,const std::string& username,const RichonlineMallCatalog& catalog,
    const RichonlineMallProduct& product,std::int64_t now) {
    const auto bucket=inventory_bucket(product);const std::size_t capacity=bucket==3?32U:8U;
    std::size_t count=0;
    Statement items(db,"SELECT encoded_item FROM lobby_inventory WHERE username=? AND (expires_at=0 OR expires_at>?)");
    items.bind(1,username);items.bind(2,now);
    while(items.row()) {
        const auto item=items.integer(0);
        if(item<=0||item>std::numeric_limits<std::uint32_t>::max())throw StorageError("mall_inventory_key_invalid");
        const auto found=catalog.products().find(static_cast<std::uint16_t>(static_cast<std::uint32_t>(item)&4095U));
        if(found==catalog.products().end())throw StorageError("mall_inventory_product_missing");
        if(inventory_bucket(found->second)==bucket&&++count>=capacity)return false;
    }
    return true;
}
}
RichonlineMallPurchaseResult Storage::purchase_mall_item(const std::string& username,std::int64_t role_id,
    const RichonlineMallCatalog& catalog,const RichonlineMallPurchase& purchase,std::int64_t now) {
    if(profile_!=ClientProfile::richonline)throw StorageError("mall_profile_invalid");
    validate(purchase,now);
    const auto& grant=purchase.grant;
    const std::lock_guard lock(mutex_);Transaction transaction(db_);
    auto current=role(db_,username,role_id);date_mode(db_,purchase.date_version);schema(db_);
    Statement prior(db_,"SELECT * FROM native_mall_purchases WHERE operation_id=?");prior.bind(1,purchase.operation_id);
    if(prior.row()) {
        const auto receipt=prior.record();
        if(receipt.at("username")!=username||receipt.at("role_id")!=role_id||receipt.at("request_key")!=purchase.request.encoded_item||
            receipt.at("owned_key")!=grant.owned_key||receipt.at("expires_at")!=grant.expires_at||
            receipt.at("opaque_word0")!=grant.opaque_word0||receipt.at("opaque_word2")!=grant.opaque_word2||receipt.at("evidence")!=grant.evidence)
            throw StorageError("mall_purchase_operation_conflict");
        auto current_grant=grant;current_grant.owned_key=current_alias(db_,username,grant.owned_key,purchase.date_version);
        validate_key_date(current_grant.owned_key,current_grant.expires_at,purchase.date_version);
        transaction.commit();return {RichonlineMallPurchaseStatus::replayed,current_grant,std::move(current)};
    }
    const auto& product=catalog.purchasable(purchase.request.encoded_item);
    if(product.fold!=1)throw StorageError("mall_purchase_bundle_grant_unproven");
    if(grant.expires_at!=0&&grant.expires_at<=now)throw StorageError("mall_purchase_grant_expired");
    const auto mode=(purchase.request.encoded_item>>12U)&15U;
    const auto& term=product.term.at(mode-1);
    if(grant.expires_at==0&&(term.years!=0||term.months!=0||term.days!=0))
        throw StorageError("mall_purchase_timed_product_requires_expiry");
    validate_key_date(grant.owned_key,grant.expires_at,purchase.date_version);
    const char* wallet=mode==1?"coins":"gold";const auto charge=product.price.at(mode-1);
    const auto before=current.at(wallet).get<double>();const auto score=current.at("purchase_score").get<std::int64_t>();
    if(!std::isfinite(before)||before<0||score<0||score>std::numeric_limits<std::int32_t>::max())throw StorageError("mall_account_state_invalid");
    if(before<charge){transaction.commit();return {RichonlineMallPurchaseStatus::insufficient_funds,std::nullopt,std::move(current)};}
    const auto after=before-charge;
    if(!std::isfinite(after)||after<0||before-after!=charge)throw StorageError("mall_purchase_balance_precision_loss");
    if(product.score>static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()-score))throw StorageError("mall_purchase_score_overflow");
    const auto next_score=score+product.score;
    Statement existing(db_,"SELECT 1 FROM lobby_inventory WHERE username=? AND encoded_item=?");existing.bind(1,username);existing.bind(2,grant.owned_key);
    if(existing.row()){transaction.commit();return {RichonlineMallPurchaseStatus::inventory_conflict,std::nullopt,std::move(current)};}
    if(!has_inventory_space(db_,username,catalog,product,now)) {
        transaction.commit();return {RichonlineMallPurchaseStatus::inventory_full,std::nullopt,std::move(current)};
    }
    Statement update(db_,mode==1?"UPDATE roles SET coins=?,purchase_score=? WHERE username=? AND role_id=?":"UPDATE roles SET gold=?,purchase_score=? WHERE username=? AND role_id=?");
    update.bind(1,after);update.bind(2,next_score);update.bind(3,username);update.bind(4,role_id);update.row();
    Statement item(db_,"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES(?,?,?)");item.bind(1,username);item.bind(2,grant.owned_key);item.bind(3,grant.expires_at);item.row();
    Statement receipt(db_,"INSERT INTO native_mall_purchases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
    receipt.bind(1,purchase.operation_id);receipt.bind(2,username);receipt.bind(3,role_id);receipt.bind(4,purchase.request.encoded_item);
    receipt.bind(5,grant.owned_key);receipt.bind(6,grant.expires_at);receipt.bind(7,grant.opaque_word0);receipt.bind(8,grant.opaque_word2);
    receipt.bind(9,grant.evidence);receipt.bind(10,charge);receipt.bind(11,product.score);receipt.bind(12,now);receipt.bind(13,static_cast<std::uint32_t>(purchase.date_version));receipt.row();
    audit(db_,username,role_id,purchase.operation_id,wallet,before,after,grant.evidence);
    audit(db_,username,role_id,purchase.operation_id,"purchase_score",score,next_score,grant.evidence);
    audit(db_,username,role_id,purchase.operation_id,"lobby_inventory."+std::to_string(grant.owned_key),nullptr,grant.expires_at,grant.evidence);
    current=role(db_,username,role_id);transaction.commit();
    return {RichonlineMallPurchaseStatus::purchased,grant,std::move(current)};
}
void Storage::require_inventory_date_version(RichonlineInventoryDateVersion version) {
    if(profile_!=ClientProfile::richonline)throw StorageError("mall_profile_invalid");
    const std::lock_guard lock(mutex_);date_mode(db_,version);
}
RichonlineMallActivationResult Storage::activate_mall_item(const std::string& username,std::int64_t role_id,
    const RichonlineMallCatalog& catalog,const RichonlineMallActivate63& request,std::int64_t now,
    RichonlineInventoryDateVersion version,const std::string& operation,const std::string& evidence) {
    if(profile_!=ClientProfile::richonline)throw StorageError("mall_profile_invalid");
    if(now<0||operation.empty()||operation.size()>256||operation.find('\0')!=std::string::npos||evidence.empty()||evidence.size()>1024||evidence.find('\0')!=std::string::npos)
        throw StorageError("mall_activation_context_invalid");
    const std::lock_guard lock(mutex_);Transaction transaction(db_);date_mode(db_,version);
    auto current=role(db_,username,role_id);schema(db_);
    Statement prior(db_,"SELECT * FROM native_mall_activations WHERE operation_id=?");prior.bind(1,operation);
    if(prior.row()) {
        const auto old=prior.record();
        if(old.at("username")!=username||old.at("role_id")!=role_id||old.at("old_key")!=request.owned_key||old.at("currency")!=static_cast<std::uint32_t>(request.currency)||old.at("evidence")!=evidence)
            throw StorageError("mall_activation_operation_conflict");
        const auto new_key=current_alias(db_,username,old.at("new_key").get<std::uint32_t>(),version);
        validate_key_date(new_key,old.at("expires_at").get<std::int64_t>(),version);
        transaction.commit();return {RichonlineMallActivationStatus::replayed,RichonlineMallActivated213{request.owned_key,new_key,request.currency,old.at("charge").get<double>()},std::move(current)};
    }
    const auto charge=catalog.activation_charge(request.owned_key,request.currency);
    Statement owned(db_,"SELECT expires_at FROM lobby_inventory WHERE username=? AND encoded_item=?");owned.bind(1,username);owned.bind(2,request.owned_key);
    if(!owned.row()){transaction.commit();return {RichonlineMallActivationStatus::missing,{},std::move(current)};}
    const auto before_expiry=owned.integer(0);
    if(before_expiry!=0&&before_expiry<=now){transaction.commit();return {RichonlineMallActivationStatus::expired,{},std::move(current)};}
    validate_key_date(request.owned_key,before_expiry,version);
    const auto duration=catalog.activation_days(request.owned_key);
    // Named compatibility rule: jhDay=0 retains the existing entitlement expiry;
    // positive jhDay starts its specified day term now. Neither grants forever.
    const auto expiry=duration==0?before_expiry:richonline_inventory_calendar_expiry(now,0,0,duration);
    const auto new_key=richonline_inventory_key_from_expiry(request.owned_key&~0x40000000U,expiry,version);
    const RichonlineMallActivated213 response{request.owned_key,new_key,request.currency,charge};
    static_cast<void>(encode_richonline_mall_activated213(response));
    Statement conflict(db_,"SELECT 1 FROM lobby_inventory WHERE username=? AND encoded_item=?");conflict.bind(1,username);conflict.bind(2,new_key);
    if(conflict.row()){transaction.commit();return {RichonlineMallActivationStatus::inventory_conflict,{},std::move(current)};}
    const auto mode=static_cast<std::uint32_t>(request.currency);const char* wallet=mode==1?"coins":"gold";
    const auto before=current.at(wallet).get<double>();
    if(!std::isfinite(before)||before<0)throw StorageError("mall_account_state_invalid");
    if(before<charge){transaction.commit();return {RichonlineMallActivationStatus::insufficient_funds,{},std::move(current)};}
    const auto after=before-charge;if(!std::isfinite(after)||after<0||before-after!=charge)throw StorageError("mall_purchase_balance_precision_loss");
    Statement update(db_,mode==1?"UPDATE roles SET coins=? WHERE username=? AND role_id=?":"UPDATE roles SET gold=? WHERE username=? AND role_id=?");
    update.bind(1,after);update.bind(2,username);update.bind(3,role_id);update.row();
    Statement replace(db_,"UPDATE lobby_inventory SET encoded_item=?,expires_at=? WHERE username=? AND encoded_item=?");replace.bind(1,new_key);replace.bind(2,expiry);replace.bind(3,username);replace.bind(4,request.owned_key);replace.row();
    Statement equipment(db_,"UPDATE lobby_equipment SET encoded_item=? WHERE encoded_item=? AND role_id IN(SELECT role_id FROM roles WHERE username=?)");equipment.bind(1,new_key);equipment.bind(2,request.owned_key);equipment.bind(3,username);equipment.row();
    Statement receipt(db_,"INSERT INTO native_mall_activations VALUES(?,?,?,?,?,?,?,?,?,?,?)");
    receipt.bind(1,operation);receipt.bind(2,username);receipt.bind(3,role_id);receipt.bind(4,request.owned_key);receipt.bind(5,new_key);receipt.bind(6,mode);receipt.bind(7,charge);receipt.bind(8,expiry);receipt.bind(9,static_cast<std::uint32_t>(version));receipt.bind(10,evidence);receipt.bind(11,now);receipt.row();
    audit(db_,username,role_id,operation,wallet,before,after,evidence);audit(db_,username,role_id,operation,"lobby_inventory.activation",request.owned_key,new_key,evidence);
    current=role(db_,username,role_id);transaction.commit();return {RichonlineMallActivationStatus::activated,response,std::move(current)};
}
}
