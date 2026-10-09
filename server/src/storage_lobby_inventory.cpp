#include "storage_detail.hpp"
#include <algorithm>
#include <limits>

namespace richnet {
using namespace storage_detail;
namespace {
constexpr std::uint32_t certificate_item=13;
constexpr std::uint32_t certificate_slot=13;
constexpr std::int64_t certificate_duration=30*24*60*60;

void require_context(ClientProfile profile,std::int64_t now) {
    if (profile!=ClientProfile::richonline) throw StorageError("lobby_inventory_profile_unsupported");
    if (now<0) throw StorageError("lobby_inventory_time_invalid");
}
void require_role(sqlite3* db,const std::string& username,std::int64_t role_id) {
    Statement role(db,"SELECT 1 FROM roles WHERE username=? AND role_id=?");
    role.bind(1,username); role.bind(2,role_id);
    if (!role.row()) throw StorageError("lobby_inventory_role_not_owned");
}
std::uint32_t equipment_at(sqlite3* db,std::int64_t role_id,std::uint32_t slot) {
    Statement equipment(db,"SELECT encoded_item FROM lobby_equipment WHERE role_id=? AND slot=?");
    equipment.bind(1,role_id); equipment.bind(2,slot);
    return equipment.row() ? static_cast<std::uint32_t>(equipment.integer(0)) : 0;
}
void audit(sqlite3* db,const std::string& username,std::int64_t role_id,
           const std::string& field,const std::string& old_value,const std::string& new_value,
           const std::string& source,const std::string& reason) {
    Statement row(db,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(?,?,?,?,?,?,?,'')");
    row.bind(1,role_id); row.bind(2,username); row.bind(3,field); row.bind(4,old_value);
    row.bind(5,new_value); row.bind(6,source); row.bind(7,reason); row.row();
}
LobbyInventory read_inventory(sqlite3* db,const std::string& username,std::int64_t role_id,std::int64_t unix_now) {
    LobbyInventory result;
    // expires_at is server-owned UTC seconds; zero denotes an untimed item, never a wire field.
    Statement items(db,"SELECT encoded_item FROM lobby_inventory WHERE username=? AND (expires_at=0 OR expires_at>?) ORDER BY encoded_item");
    items.bind(1,username); items.bind(2,unix_now);
    while (items.row()) result.items.push_back(static_cast<std::uint32_t>(items.integer(0)));
    Statement equipped(db,"SELECT slot,encoded_item FROM lobby_equipment WHERE role_id=? ORDER BY slot");
    equipped.bind(1,role_id);
    while (equipped.row()) {
        const auto item=static_cast<std::uint32_t>(equipped.integer(1));
        if (std::binary_search(result.items.begin(),result.items.end(),item))
            result.equipment.at(static_cast<std::size_t>(equipped.integer(0)))=item;
    }
    return result;
}
}

LobbyInventory Storage::lobby_inventory(const std::string& username,std::int64_t role_id,std::int64_t unix_now) {
    const std::lock_guard lock(mutex_);
    require_context(profile_,unix_now);
    Transaction transaction(db_,false);
    require_role(db_,username,role_id);
    auto result=read_inventory(db_,username,role_id,unix_now);
    transaction.commit();
    return result;
}

LobbyInventory Storage::lobby_inventory_for_role(std::int64_t role_id,std::int64_t unix_now) {
    const std::lock_guard lock(mutex_);
    require_context(profile_,unix_now);
    Transaction transaction(db_,false);
    Statement owner(db_,"SELECT username FROM roles WHERE role_id=?");
    owner.bind(1,role_id);
    if (!owner.row()) throw StorageError("lobby_inventory_role_missing");
    auto result=read_inventory(db_,owner.text(0),role_id,unix_now);
    transaction.commit();
    return result;
}

RpCertificateGrant Storage::ensure_test_rp_certificate(const std::string& username,std::int64_t unix_now) {
    const std::lock_guard lock(mutex_);
    require_context(profile_,unix_now);
    if (unix_now>std::numeric_limits<std::int64_t>::max()-certificate_duration)
        throw StorageError("lobby_inventory_time_invalid");
    Transaction transaction(db_);
    std::vector<std::int64_t> roles;
    Statement owned(db_,"SELECT role_id FROM roles WHERE username=? ORDER BY role_id");
    owned.bind(1,username);
    while (owned.row()) roles.push_back(owned.integer(0));
    if (roles.empty()) throw StorageError("lobby_inventory_account_has_no_roles");
    RpCertificateGrant result;
    std::optional<std::int64_t> previous_expiry;
    {
        Statement item(db_,"SELECT expires_at FROM lobby_inventory WHERE username=? AND encoded_item=?");
        item.bind(1,username); item.bind(2,certificate_item);
        if (item.row()) previous_expiry=item.integer(0);
    }
    if (!previous_expiry || (*previous_expiry!=0 && *previous_expiry<=unix_now)) {
        const auto expires=unix_now+certificate_duration;
        Statement item(db_,"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES(?,?,?) ON CONFLICT(username,encoded_item) DO UPDATE SET expires_at=excluded.expires_at");
        item.bind(1,username); item.bind(2,certificate_item); item.bind(3,expires); item.row();
        result.granted=!previous_expiry.has_value();
        result.renewed=previous_expiry.has_value();
        audit(db_,username,roles.front(),"lobby_inventory.13.expires_at",
              previous_expiry ? std::to_string(*previous_expiry) : "absent",std::to_string(expires),
              "native-test-rp-policy","Explicit test policy grants or renews a 30-day RP certificate");
    }
    for (const auto role_id:roles) {
        const auto current=equipment_at(db_,role_id,certificate_slot);
        if (current==certificate_item) continue;
        if (current!=0) { ++result.conflicts; continue; }
        Statement equip(db_,"INSERT INTO lobby_equipment(role_id,slot,encoded_item) VALUES(?,?,?)");
        equip.bind(1,role_id); equip.bind(2,certificate_slot); equip.bind(3,certificate_item); equip.row();
        ++result.equipped;
        audit(db_,username,role_id,"lobby_equipment.13","0","13","native-test-rp-policy",
              "Explicit test policy equips the owned RP certificate in an empty POCKET slot");
    }
    transaction.commit();
    return result;
}

void Storage::update_lobby_equipment(const std::string& username,const LobbyEquipmentChange& change,std::int64_t unix_now) {
    const std::lock_guard lock(mutex_);
    require_context(profile_,unix_now);
    if (change.slot>=32) throw StorageError("lobby_equipment_slot_invalid");
    Transaction transaction(db_);
    require_role(db_,username,change.role_id);
    if (equipment_at(db_,change.role_id,change.slot)!=change.expected_item)
        throw StorageError("lobby_equipment_stale");
    if (change.item!=0) {
        Statement item(db_,"SELECT 1 FROM lobby_inventory WHERE username=? AND encoded_item=? AND (expires_at=0 OR expires_at>?)");
        item.bind(1,username); item.bind(2,change.item); item.bind(3,unix_now);
        if (!item.row()) throw StorageError("lobby_equipment_item_not_owned_or_expired");
    }
    if (change.item==change.expected_item) { transaction.commit(); return; }
    if (change.item==0) {
        Statement remove(db_,"DELETE FROM lobby_equipment WHERE role_id=? AND slot=?");
        remove.bind(1,change.role_id); remove.bind(2,change.slot); remove.row();
    } else {
        Statement equip(db_,"INSERT INTO lobby_equipment(role_id,slot,encoded_item) VALUES(?,?,?) ON CONFLICT(role_id,slot) DO UPDATE SET encoded_item=excluded.encoded_item");
        equip.bind(1,change.role_id); equip.bind(2,change.slot); equip.bind(3,change.item); equip.row();
    }
    audit(db_,username,change.role_id,"lobby_equipment."+std::to_string(change.slot),
          std::to_string(change.expected_item),std::to_string(change.item),"native-lobby-equipment",
          "Ownership-validated equipment compare-and-swap");
    transaction.commit();
}
}
