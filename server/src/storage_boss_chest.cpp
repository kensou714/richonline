#include "storage_detail.hpp"
#include <charconv>

namespace richnet {
using namespace storage_detail;
namespace {
using Json=nlohmann::json;
std::uint32_t term_field(const RichonlineMallProduct& item,const char* key) {
    const auto found=item.source_fields.find(key);
    if(found==item.source_fields.end()) return 0;
    const auto& text=found->second;std::uint32_t result=0;
    const auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
    if(parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || result>36600)
        throw StorageError("boss_chest_term_invalid");
    return result;
}
std::size_t bucket(const RichonlineMallProduct& item) {
    if(item.type=="AVATAR") return 3;
    if(item.type=="FUNC") return 2;
    if(item.type=="CARD" && item.subtype=="CARD_CQ") return 1;
    if(item.type=="CARD" && item.subtype=="CARD_GL") return 0;
    throw StorageError("boss_chest_product_category_invalid");
}
}
GameBossChestReceipt Storage::claim_boss_chest(const std::string& username,std::int64_t role_id,
    const RichonlineMallCatalog& catalog,const GameBossChestClaim& request,std::int64_t now) {
    const auto& drop=request.drop;
    if(profile_!=ClientProfile::richonline || now<0 || request.settlement_operation.empty() ||
        request.settlement_operation.size()>240 || request.settlement_operation.find('\0')!=std::string::npos ||
        request.stage_key.empty() || request.stage_key.size()>128 || request.stage_key.find('\0')!=std::string::npos ||
        drop.weight==0 || (drop.kind==RichonlineBossDropKind::skill ? drop.id>=10 || drop.level<1 || drop.level>7 :
            drop.id<1 || drop.id>4095 || drop.level!=0))
        throw StorageError("boss_chest_claim_invalid");
    for(const auto cap:request.skill_caps) if(cap<0 || cap>7) throw StorageError("boss_chest_skills_invalid");
    const auto kind=drop.kind==RichonlineBossDropKind::skill ? "skill" :
        drop.kind==RichonlineBossDropKind::active_item ? "active" : "inactive";
    const Json canonical{{"username",username},{"role",role_id},{"settlement",request.settlement_operation},
        {"stage",request.stage_key},{"kind",kind},{"id",drop.id},{"level",drop.level},{"weight",drop.weight},
        {"skill_caps",request.skill_caps},{"allow_server_only_expiry",request.allow_server_only_expiry}};
    const auto operation=request.settlement_operation+":chest";
    const std::lock_guard lock(mutex_);Transaction transaction(db_);
    Statement victory(db_,"SELECT s.outcome,s.stage_key,o.source,o.request FROM game_settlements s "
        "JOIN operations o ON o.operation_id=s.operation_id JOIN roles r ON r.role_id=s.role_id "
        "WHERE s.operation_id=? AND s.role_id=? AND r.username=?");
    victory.bind(1,request.settlement_operation);victory.bind(2,role_id);victory.bind(3,username);
    if(!victory.row() || victory.text(0)!="win" || victory.text(1)!=request.stage_key ||
        victory.text(2)!="native-game-settlement" || Json::parse(victory.text(3)).at("username")!=username)
        throw StorageError("boss_chest_committed_victory_required");
    execute(db_,R"sql(CREATE TABLE IF NOT EXISTS game_boss_chests(
 settlement_operation TEXT PRIMARY KEY REFERENCES operations(operation_id),
 claim_operation TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
 role_id INTEGER NOT NULL REFERENCES roles(role_id),kind TEXT NOT NULL,reward_id INTEGER NOT NULL,
 reward_level INTEGER NOT NULL,status TEXT NOT NULL,owned_key INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,inventory_id INTEGER) STRICT;)sql");
    Statement previous(db_,"SELECT role_id,source,request,result FROM operations WHERE operation_id=?");previous.bind(1,operation);
    if(previous.row()) {
        if(previous.integer(0)!=role_id || previous.text(1)!="native-boss-chest" || previous.text(2)!=canonical.dump())
            throw StorageError("boss_chest_operation_conflict");
        const auto result=Json::parse(previous.text(3));
        transaction.commit();return {true,result.at("discarded"),result.at("pending_date"),result.at("owned_key"),result.at("expires_at")};
    }
    GameBossChestReceipt receipt;
    std::string state;
    if(drop.kind==RichonlineBossDropKind::skill) {
        // 技能奖励先保存每一级所有权；目前全7级配置下为已拥有，绝不降级账号。
        execute(db_,R"sql(CREATE TABLE IF NOT EXISTS game_boss_skill_rewards(
 role_id INTEGER NOT NULL REFERENCES roles(role_id),skill INTEGER NOT NULL CHECK(skill BETWEEN 0 AND 9),
 level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 7),operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 PRIMARY KEY(role_id,skill,level)) STRICT;)sql");
        state=drop.level<=request.skill_caps[drop.id] ? "skill_already_owned" : "skill_recorded";
    } else {
        const auto item=catalog.products().find(drop.id);
        if(item==catalog.products().end()) throw StorageError("boss_chest_product_missing");
        Statement mode(db_,"SELECT value FROM metadata WHERE key='inventory_date_version'");
        const auto version=mode.row()?mode.text(0):"original-2005";
        if(version!="original-2005" && version!=richonline_inventory_compatibility_id)
            throw StorageError("boss_chest_date_mode_invalid");
        const auto epoch=version=="original-2005" ? RichonlineInventoryDateVersion::original_2005 :
            RichonlineInventoryDateVersion::compat_2021_v1;
        const auto years=term_field(item->second,"yearP"),months=term_field(item->second,"monthP"),days=term_field(item->second,"dayP");
        receipt.expires_at=years || months || days ? richonline_inventory_calendar_expiry(now,years,months,days) : 0;
        const auto base=static_cast<std::uint32_t>(drop.id) |
            (drop.kind==RichonlineBossDropKind::inactive_item ? 0x40000000U : 0U);
        const auto expiry_year=receipt.expires_at ? richonline_inventory_utc_date(receipt.expires_at).year : 0;
        const auto first_year=static_cast<int>(epoch);
        const bool date_fits=!receipt.expires_at || (expiry_year>=first_year && expiry_year<=first_year+15);
        receipt.pending_date=!date_fits && !request.allow_server_only_expiry;
        receipt.owned_key=date_fits ? richonline_inventory_key_from_expiry(base,receipt.expires_at,epoch) : base;
        std::size_t count=0;const auto category=bucket(item->second);
        Statement owned(db_,"SELECT encoded_item FROM lobby_inventory WHERE username=? AND (expires_at=0 OR expires_at>?)");
        owned.bind(1,username);owned.bind(2,now);
        while(owned.row()) {
            const auto key=owned.integer(0);
            if(key<=0 || key>2147483647) throw StorageError("boss_chest_inventory_key_invalid");
            const auto product=catalog.products().find(static_cast<std::uint16_t>(key&4095));
            if(product==catalog.products().end()) throw StorageError("boss_chest_inventory_product_missing");
            if(bucket(product->second)==category) ++count;
        }
        receipt.discarded=count>=(category==3 ? 32U : 8U);
        if(receipt.discarded) receipt.pending_date=false;
        state=receipt.discarded ? "discarded_full" : receipt.pending_date ? "pending_date" : "granted";
    }
    const Json result{{"discarded",receipt.discarded},{"pending_date",receipt.pending_date},
        {"owned_key",receipt.owned_key},{"expires_at",receipt.expires_at},{"status",state}};
    Statement operation_row(db_,"INSERT INTO operations(operation_id,role_id,source,reason,request,result) "
        "VALUES(?,?,'native-boss-chest','BossWar dropBox weighted reward',?,?)");
    operation_row.bind(1,operation);operation_row.bind(2,role_id);operation_row.bind(3,canonical.dump());operation_row.bind(4,result.dump());operation_row.row();
    std::optional<std::int64_t> inventory_id;
    if(drop.kind==RichonlineBossDropKind::skill) {
        Statement skill(db_,"INSERT OR IGNORE INTO game_boss_skill_rewards VALUES(?,?,?,?)");
        skill.bind(1,role_id);skill.bind(2,drop.id);skill.bind(3,drop.level);skill.bind(4,operation);skill.row();
    } else if(!receipt.discarded && !receipt.pending_date) {
        Statement add(db_,"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES(?,?,?)");
        add.bind(1,username);add.bind(2,receipt.owned_key);add.bind(3,receipt.expires_at);add.row();
        inventory_id=sqlite3_last_insert_rowid(db_);
    }
    Statement chest(db_,"INSERT INTO game_boss_chests VALUES(?,?,?,?,?,?,?,?,?,?,?)");
    chest.bind(1,request.settlement_operation);chest.bind(2,operation);chest.bind(3,role_id);chest.bind(4,kind);
    chest.bind(5,drop.id);chest.bind(6,drop.level);chest.bind(7,state);chest.bind(8,receipt.owned_key);chest.bind(9,receipt.expires_at);chest.bind(10,now);
    chest.bind(11,inventory_id ? Json(*inventory_id) : Json(nullptr));chest.row();
    Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) "
        "VALUES(?,?,'boss_chest','null',?,'native-boss-chest','BossWar dropBox weighted reward',?)");
    audit.bind(1,role_id);audit.bind(2,username);audit.bind(3,result.dump());audit.bind(4,operation);audit.row();
    transaction.commit();return receipt;
}
std::int64_t Storage::boss_chest_cursor() {
    const std::lock_guard lock(mutex_);
    Statement exists(db_,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='game_boss_chests'");
    if(!exists.row()) return 0;
    Statement cursor(db_,"SELECT COALESCE(MAX(rowid),0) FROM game_boss_chests");
    if(!cursor.row()) throw StorageError("boss_chest_cursor_missing");
    return cursor.integer(0);
}
std::vector<GameBossChestNotice> Storage::boss_chest_notices(const std::string& username,std::int64_t role,
    const std::string& operation,std::int64_t after,std::int64_t now) {
    const std::lock_guard lock(mutex_);
    Statement exists(db_,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='game_boss_chests'");
    if(!exists.row()) return {};
    Statement rows(db_,"SELECT c.rowid,i.encoded_item FROM game_boss_chests c JOIN lobby_inventory i ON i.inventory_id=c.inventory_id "
        "JOIN roles r ON r.role_id=c.role_id WHERE c.rowid>? AND c.role_id=? AND r.username=? AND i.username=? "
        "AND c.settlement_operation=? AND c.status='granted' AND (i.expires_at=0 OR i.expires_at>?) ORDER BY c.rowid");
    rows.bind(1,after);rows.bind(2,role);rows.bind(3,username);rows.bind(4,username);rows.bind(5,operation);rows.bind(6,now);
    std::vector<GameBossChestNotice> result;
    while(rows.row()) result.push_back({rows.integer(0),static_cast<std::uint32_t>(rows.integer(1))});
    return result;
}
std::array<std::int8_t,10> Storage::boss_skill_caps(std::int64_t role,std::array<std::int8_t,10> baseline) {
    const std::lock_guard lock(mutex_);
    Statement exists(db_,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='game_boss_skill_rewards'");
    if(!exists.row()) return baseline;
    Statement rows(db_,"SELECT skill,level FROM game_boss_skill_rewards WHERE role_id=? ORDER BY skill,level");rows.bind(1,role);
    while(rows.row()) {
        const auto skill=rows.integer(0),level=rows.integer(1);
        if(skill<0 || skill>=10 || level<1 || level>7) throw StorageError("boss_chest_stored_skill_invalid");
        auto& cap=baseline[static_cast<std::size_t>(skill)];
        // 越级奖励保留，拥有连续前置等级后才启用，不直接把1级跳到6级。
        if(level==cap+1) cap=static_cast<std::int8_t>(level);
    }
    return baseline;
}
}
