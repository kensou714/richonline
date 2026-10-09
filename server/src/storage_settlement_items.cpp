#include "storage_detail.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <set>

namespace richnet {
using namespace storage_detail;
namespace {
using Json=nlohmann::json;
constexpr const char* source="native-game-item-resolution";
void text(const std::string& value,std::size_t maximum) {
    if(value.empty()||value.size()>maximum||value.find('\0')!=std::string::npos)
        throw StorageError("game_settlement_items_policy_invalid");
}
const char* activation_name(GameSettlementItemActivation value) {
    switch(value) {
    case GameSettlementItemActivation::active:return "active";
    case GameSettlementItemActivation::requires_activation:return "requires_activation";
    }
    throw StorageError("game_settlement_items_activation_invalid");
}
const char* version_name(RichonlineInventoryDateVersion value) {
    switch(value) {
    case RichonlineInventoryDateVersion::original_2005:return "original-2005";
    case RichonlineInventoryDateVersion::compat_2021_v1:return "richonline-inventory-date-2021-v1";
    }
    throw StorageError("game_settlement_items_date_version_invalid");
}
Json instance_json(const GameSettlementItemInstance& value) {
    return {{"owned_key",value.owned_key},{"expires_at",value.expires_at?Json(*value.expires_at):Json(nullptr)},
        {"activation",activation_name(value.activation)}};
}
Json canonical(const std::string& username,std::int64_t role,const GameSettlementItemResolution& request) {
    Json selections=Json::array();
    for(const auto& selected:request.selections) {
        Json instances=Json::array();for(const auto& item:selected.instances)instances.push_back(instance_json(item));
        selections.push_back({{"resource_index",selected.resource_index},{"quantity",selected.quantity},{"instances",instances}});
    }
    return {{"username",username},{"role_id",role},{"settlement_operation",request.settlement_operation},
        {"policy_identifier",request.policy_identifier},{"evidence",request.evidence},
        {"key_date_version",version_name(request.key_date_version)},{"selections",selections}};
}
Json result_json(const GameSettlementItemResolution& request) {
    Json items=Json::array();
    for(const auto& selected:request.selections)for(const auto& item:selected.instances) {
        auto value=instance_json(item);value["resource_index"]=selected.resource_index;items.push_back(std::move(value));
    }
    return {{"items",items}};
}
void validate(const GameSettlementItemResolution& request) {
    text(request.operation_id,256);text(request.settlement_operation,256);
    text(request.policy_identifier,128);text(request.evidence,1024);(void)version_name(request.key_date_version);
    if(request.operation_id==request.settlement_operation||request.selections.empty()||request.selections.size()>8)
        throw StorageError("game_settlement_items_selection_invalid");
    std::set<std::uint32_t> indices,keys;std::size_t units=0;
    for(const auto& selected:request.selections) {
        if(!indices.insert(selected.resource_index).second||selected.quantity==0||selected.quantity>56||
            selected.instances.size()!=selected.quantity)
            throw StorageError("game_settlement_items_quantity_invalid");
        units+=selected.instances.size();if(units>56)throw StorageError("game_settlement_items_quantity_invalid");
        for(const auto& item:selected.instances) {
            const auto key=item.owned_key;(void)activation_name(item.activation);
            if((key&4095U)==0||(key&0x80000000U)!=0||((key>>12U)&15U)>2||
                (key&0x10000U)!=0||((key&0x40000000U)!=0)!=(item.activation==GameSettlementItemActivation::requires_activation))
                throw StorageError("game_settlement_items_key_state_invalid");
            if(!keys.insert(key).second)throw StorageError("game_settlement_items_duplicate_key");
            if(item.expires_at&&*item.expires_at<=0)throw StorageError("game_settlement_items_expiry_invalid");
            try {
                if(richonline_inventory_key_from_expiry(key,item.expires_at.value_or(0),request.key_date_version)!=key)
                    throw StorageError("game_settlement_items_key_date_mismatch");
            }catch(const CodecError&){throw StorageError("game_settlement_items_key_date_mismatch");}
        }
    }
}
void guard(sqlite3* db,const GameSettlementItemClientGuard& value) {
    const auto expected=version_name(value.date_version);
    if((value.date_version==RichonlineInventoryDateVersion::original_2005&&!value.verified_client_compatibility_id.empty())||
        (value.date_version==RichonlineInventoryDateVersion::compat_2021_v1&&
            value.verified_client_compatibility_id!=richonline_inventory_compatibility_id))
        throw StorageError("game_settlement_items_client_guard_invalid");
    Statement mode(db,"SELECT value FROM metadata WHERE key='inventory_date_version'");
    if((mode.row()?mode.text(0):"original-2005")!=expected)
        throw StorageError("inventory_date_database_mode_mismatch");
}
void schema(sqlite3* db) {
    execute(db,R"sql(CREATE TABLE IF NOT EXISTS game_settlement_item_resolutions(
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 settlement_operation TEXT NOT NULL UNIQUE REFERENCES game_settlement_item_rewards(operation_id),
 role_id INTEGER NOT NULL REFERENCES roles(role_id),policy_identifier TEXT NOT NULL,evidence TEXT NOT NULL,
 date_version INTEGER NOT NULL CHECK(date_version IN (2005,2021)),
 grant_count INTEGER NOT NULL CHECK(grant_count BETWEEN 1 AND 56)) STRICT;)sql");
}
std::size_t bucket(const RichonlineMallProduct& product) {
    if(product.type=="CARD"&&product.subtype=="CARD_GL")return 0;
    if(product.type=="CARD"&&product.subtype=="CARD_CQ")return 1;
    if(product.type=="FUNC")return 2;
    if(product.type=="AVATAR")return 3;
    throw StorageError("game_settlement_items_category_invalid");
}
const RichonlineMallProduct& product(const RichonlineMallCatalog& catalog,std::uint32_t key) {
    const auto found=catalog.products().find(static_cast<std::uint16_t>(key&4095U));
    if(found==catalog.products().end())throw StorageError("game_settlement_items_product_missing");return found->second;
}
std::uint32_t current_key(sqlite3* db,const std::string& username,std::uint32_t key,
    RichonlineInventoryDateVersion old_version,RichonlineInventoryDateVersion new_version) {
    if(old_version==new_version)return key;
    Statement exists(db,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='inventory_key_aliases'");
    if(!exists.row())throw StorageError("game_settlement_items_alias_missing");
    Statement alias(db,"SELECT new_key FROM inventory_key_aliases WHERE username=? AND old_key=? AND old_version=? AND new_version=?");
    alias.bind(1,username);alias.bind(2,key);alias.bind(3,static_cast<std::uint16_t>(old_version));
    alias.bind(4,static_cast<std::uint16_t>(new_version));
    if(!alias.row())throw StorageError("game_settlement_items_alias_missing");
    const auto mapped=alias.integer(0);
    if(mapped<=0||mapped>2147483647||alias.row())throw StorageError("game_settlement_items_alias_invalid");
    return static_cast<std::uint32_t>(mapped);
}
std::vector<GameSettlementResolvedItem> current_items(sqlite3* db,const std::string& username,
    const GameSettlementItemResolution& request,RichonlineInventoryDateVersion current_version,std::int64_t now) {
    std::vector<GameSettlementResolvedItem> result;
    for(const auto& selected:request.selections)for(const auto& item:selected.instances) {
        std::optional<std::uint32_t> current;
        if(!item.expires_at||*item.expires_at>now) {
            // No-date permanent keys are epoch-independent. A dated entitlement
            // crossing epochs requires an explicit immutable migration alias.
            const auto key=!item.expires_at?item.owned_key:
                current_key(db,username,item.owned_key,request.key_date_version,current_version);
            try {
                if(richonline_inventory_key_from_expiry(key,item.expires_at.value_or(0),current_version)!=key||
                    (key&0xc001ffffU)!=(item.owned_key&0xc001ffffU))
                    throw StorageError("game_settlement_items_alias_invalid");
            }catch(const CodecError&){throw StorageError("game_settlement_items_alias_invalid");}
            Statement owned(db,"SELECT expires_at FROM lobby_inventory WHERE username=? AND encoded_item=?");
            owned.bind(1,username);owned.bind(2,key);
            if(owned.row()) {
                if(owned.integer(0)!=item.expires_at.value_or(0))throw StorageError("game_settlement_items_inventory_changed");
                current=key;
            }
        }
        result.push_back({selected.resource_index,item.owned_key,current,item.expires_at,item.activation});
    }
    return result;
}
void require_object(const Json& value,std::initializer_list<const char*> keys) {
    if(!value.is_object()||value.size()!=keys.size())throw CodecError("game_settlement_items_config_shape_invalid");
    for(const auto* key:keys)if(!value.contains(key))throw CodecError("game_settlement_items_config_shape_invalid");
}
std::uint32_t integer(const Json& value,std::uint32_t maximum) {
    if(!value.is_number_integer()||value<0||value>maximum)throw CodecError("game_settlement_items_config_number_invalid");
    return value.get<std::uint32_t>();
}
}
GameSettlementItemResolution decode_game_settlement_item_resolution(const Json& value) {
    try {
        require_object(value,{"operation_id","settlement_operation","policy_identifier","evidence","key_date_version","selections"});
        const auto mode=value.at("key_date_version").get<std::string>();
        if(mode!="original-2005"&&mode!=richonline_inventory_compatibility_id)
            throw CodecError("game_settlement_items_config_date_version_invalid");
        GameSettlementItemResolution result{value.at("operation_id").get<std::string>(),value.at("settlement_operation").get<std::string>(),
            value.at("policy_identifier").get<std::string>(),value.at("evidence").get<std::string>(),
            mode=="original-2005"?RichonlineInventoryDateVersion::original_2005:RichonlineInventoryDateVersion::compat_2021_v1,{}};
        if(!value.at("selections").is_array())throw CodecError("game_settlement_items_config_shape_invalid");
        for(const auto& selected:value.at("selections")) {
            require_object(selected,{"resource_index","quantity","instances"});
            GameSettlementItemSelection selection{integer(selected.at("resource_index"),7),integer(selected.at("quantity"),56),{}};
            if(!selected.at("instances").is_array())throw CodecError("game_settlement_items_config_shape_invalid");
            for(const auto& item:selected.at("instances")) {
                require_object(item,{"owned_key","expires_at","activation"});
                const auto activation=item.at("activation").get<std::string>();
                if(activation!="active"&&activation!="requires_activation")throw CodecError("game_settlement_items_config_activation_invalid");
                std::optional<std::int64_t> expiry;
                if(!item.at("expires_at").is_null()) {
                    if(!item.at("expires_at").is_number_integer()||item.at("expires_at")<=0||
                        item.at("expires_at")>std::numeric_limits<std::int64_t>::max())
                        throw CodecError("game_settlement_items_config_number_invalid");
                    expiry=item.at("expires_at").get<std::int64_t>();
                }
                selection.instances.push_back({integer(item.at("owned_key"),2147483647U),expiry,
                    activation=="active"?GameSettlementItemActivation::active:GameSettlementItemActivation::requires_activation});
            }
            result.selections.push_back(std::move(selection));
        }
        validate(result);return result;
    }catch(const Json::exception&){throw CodecError("game_settlement_items_config_shape_invalid");}
     catch(const StorageError& error){throw CodecError(error.what());}
}
GameSettlementItemResolutionResult Storage::resolve_game_settlement_items(const std::string& username,std::int64_t role,
    const RichonlineMallCatalog& catalog,const GameSettlementItemResolution& request,
    const GameSettlementItemClientGuard& client,std::int64_t now) {
    if(profile_!=ClientProfile::richonline)throw StorageError("game_settlement_items_profile_invalid");
    validate(request);if(now<0)throw StorageError("game_settlement_items_clock_invalid");
    const auto expected=canonical(username,role,request),expected_result=result_json(request);
    const std::lock_guard lock(mutex_);Transaction transaction(db_);guard(db_,client);
    Statement owner(db_,"SELECT 1 FROM roles WHERE username=? AND role_id=?");owner.bind(1,username);owner.bind(2,role);
    if(!owner.row())throw StorageError("game_settlement_items_role_not_owned");
    Statement exists(db_,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='game_settlement_item_rewards'");
    if(!exists.row())throw StorageError("game_settlement_items_intent_missing");
    schema(db_);
    Statement intent(db_,"SELECT r.role_id,r.resource_count,r.resource_ids,r.match_id,r.stage_key,r.provenance,o.source,o.request,o.result "
        "FROM game_settlement_item_rewards r JOIN operations o ON o.operation_id=r.operation_id WHERE r.operation_id=?");
    intent.bind(1,request.settlement_operation);
    if(!intent.row()||intent.integer(0)!=role)throw StorageError("game_settlement_items_intent_missing");
    std::vector<std::int32_t> resource_ids;
    try {
        const auto original=Json::parse(intent.text(7)),receipt=Json::parse(intent.text(8)),ids=Json::parse(intent.text(2));
        if(intent.text(6)!="native-game-settlement"||original.at("username")!=username||original.at("role_id")!=role||
            original.at("match_id")!=intent.text(3)||original.at("stage_key")!=intent.text(4)||
            original.at("policy").at("provenance")!=intent.text(5)||!ids.is_array()||intent.integer(1)<1||intent.integer(1)>8||
            ids.size()!=static_cast<std::size_t>(intent.integer(1))||
            receipt.at("reward").at("items")!=Json{{"resource_count",intent.integer(1)},{"resource_ids",ids}})
            throw StorageError("game_settlement_items_intent_invalid");
        for(const auto& id:ids) {
            if(!id.is_number_integer()||id<std::numeric_limits<std::int32_t>::min()||id>std::numeric_limits<std::int32_t>::max())
                throw StorageError("game_settlement_items_intent_invalid");
            resource_ids.push_back(id.get<std::int32_t>());
        }
    }catch(const Json::exception&){throw StorageError("game_settlement_items_intent_invalid");}
    std::array<std::size_t,4> incoming{};
    for(const auto& selected:request.selections) {
        if(selected.resource_index>=resource_ids.size()||resource_ids[selected.resource_index]<=0||resource_ids[selected.resource_index]>4095)
            throw StorageError("game_settlement_items_resource_index_invalid");
        for(const auto& item:selected.instances) {
            if((item.owned_key&4095U)!=static_cast<std::uint32_t>(resource_ids[selected.resource_index]))
                throw StorageError("game_settlement_items_product_mismatch");
            ++incoming[bucket(product(catalog,item.owned_key))];
        }
    }
    Statement prior(db_,"SELECT role_id,source,request,result FROM operations WHERE operation_id=?");prior.bind(1,request.operation_id);
    if(prior.row()) {
        if(prior.integer(0)!=role||prior.text(1)!=source||prior.text(2)!=expected.dump()||prior.text(3)!=expected_result.dump())
            throw StorageError("game_settlement_items_operation_conflict");
        Statement link(db_,"SELECT settlement_operation,role_id,policy_identifier,evidence,date_version,grant_count FROM game_settlement_item_resolutions WHERE operation_id=?");
        link.bind(1,request.operation_id);
        if(!link.row()||link.text(0)!=request.settlement_operation||link.integer(1)!=role||link.text(2)!=request.policy_identifier||
            link.text(3)!=request.evidence||link.integer(4)!=static_cast<std::uint16_t>(request.key_date_version)||
            link.integer(5)!=static_cast<std::int64_t>(expected_result.at("items").size()))
            throw StorageError("game_settlement_items_receipt_invalid");
        auto result=current_items(db_,username,request,client.date_version,now);transaction.commit();
        return {GameSettlementItemResolutionStatus::replayed,std::move(result)};
    }
    Statement resolved(db_,"SELECT 1 FROM game_settlement_item_resolutions WHERE settlement_operation=?");resolved.bind(1,request.settlement_operation);
    if(resolved.row())throw StorageError("game_settlement_items_already_resolved");
    if(request.key_date_version!=client.date_version)throw StorageError("game_settlement_items_new_grant_epoch_mismatch");
    for(const auto& selected:request.selections)for(const auto& item:selected.instances) {
        if(item.expires_at&&*item.expires_at<=now)throw StorageError("game_settlement_items_grant_expired");
        Statement owned(db_,"SELECT 1 FROM lobby_inventory WHERE username=? AND encoded_item=?");owned.bind(1,username);owned.bind(2,item.owned_key);
        if(owned.row()){transaction.commit();return {GameSettlementItemResolutionStatus::inventory_conflict,{}};}
    }
    std::array<std::size_t,4> counts{};
    Statement inventory(db_,"SELECT encoded_item FROM lobby_inventory WHERE username=? AND (expires_at=0 OR expires_at>?)");
    inventory.bind(1,username);inventory.bind(2,now);
    while(inventory.row()) {
        const auto key=inventory.integer(0);
        if(key<=0||key>2147483647)throw StorageError("game_settlement_items_stored_key_invalid");
        ++counts[bucket(product(catalog,static_cast<std::uint32_t>(key)))];
    }
    constexpr std::array<std::size_t,4> capacity{8,8,8,32};
    for(std::size_t i=0;i<capacity.size();++i)if(counts[i]>capacity[i]||incoming[i]>capacity[i]-counts[i]) {
        transaction.commit();return {GameSettlementItemResolutionStatus::inventory_full,{}};
    }
    Statement receipt(db_,"INSERT INTO operations(operation_id,role_id,source,reason,request,result) VALUES(?,?,?,?,?,?)");
    receipt.bind(1,request.operation_id);receipt.bind(2,role);receipt.bind(3,source);receipt.bind(4,request.evidence);
    receipt.bind(5,expected.dump());receipt.bind(6,expected_result.dump());receipt.row();
    for(const auto& selected:request.selections)for(const auto& item:selected.instances) {
        Statement add(db_,"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES(?,?,?)");
        add.bind(1,username);add.bind(2,item.owned_key);add.bind(3,item.expires_at.value_or(0));add.row();
        auto value=instance_json(item);value["resource_index"]=selected.resource_index;value["policy_identifier"]=request.policy_identifier;
        value["key_date_version"]=version_name(request.key_date_version);
        Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,'null',?,?,?,?)");
        audit.bind(1,role);audit.bind(2,username);audit.bind(3,"lobby_inventory."+std::to_string(item.owned_key));
        audit.bind(4,value.dump());audit.bind(5,source);audit.bind(6,request.evidence);audit.bind(7,request.operation_id);audit.row();
    }
    Statement close(db_,"INSERT INTO game_settlement_item_resolutions VALUES(?,?,?,?,?,?,?)");
    close.bind(1,request.operation_id);close.bind(2,request.settlement_operation);close.bind(3,role);
    close.bind(4,request.policy_identifier);close.bind(5,request.evidence);close.bind(6,static_cast<std::uint16_t>(request.key_date_version));
    close.bind(7,expected_result.at("items").size());close.row();
    auto result=current_items(db_,username,request,client.date_version,now);transaction.commit();
    return {GameSettlementItemResolutionStatus::resolved,std::move(result)};
}
}
