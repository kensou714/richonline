#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <future>
#include <iostream>
#include <latch>

namespace {
using namespace richnet;
using Json=nlohmann::json;
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F> void reject(F fn,const std::string& expected) {
    try {fn();}catch(const std::exception& error){check(error.what()==expected,"unexpected_rejection");return;}
    throw std::runtime_error("missing_rejection");
}
class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db_)==SQLITE_OK,"fixture_open");
    }
    ~Database(){sqlite3_close(db_);}
    void exec(const std::string& sql){check(sqlite3_exec(db_,sql.c_str(),nullptr,nullptr,nullptr)==SQLITE_OK,"fixture_sql");}
    std::int64_t scalar(const char* sql) {
        sqlite3_stmt* statement=nullptr;check(sqlite3_prepare_v2(db_,sql,-1,&statement,nullptr)==SQLITE_OK,"fixture_prepare");
        check(sqlite3_step(statement)==SQLITE_ROW,"fixture_scalar");const auto value=sqlite3_column_int64(statement,0);
        sqlite3_finalize(statement);return value;
    }
private:sqlite3* db_{};
};
constexpr std::int64_t now=1500000000,expiry=1514851200;
constexpr auto original=RichonlineInventoryDateVersion::original_2005,compat=RichonlineInventoryDateVersion::compat_2021_v1;
const GameSettlementItemClientGuard original_guard{original,""},compat_guard{compat,std::string(richonline_inventory_compatibility_id)};
RichonlineMallCatalog catalog() {
    const std::string props="[PROP]\nindx=1125\nname=card\ntype=CARD\nchType=CARD_GL\nenable=true\ndayP=365\n"
        "[PROP]\nindx=200\nname=avatar\ntype=AVATAR\nchType=AVATAR_BS\nenable=true\ndayP=1\n"
        "[PROP]\nindx=201\nname=avatar2\ntype=AVATAR\nchType=AVATAR_TX\nenable=true\ndayP=2\n";
    const std::string sale="; fixture has no sale offers\n";
    return RichonlineMallCatalog::parse(View(reinterpret_cast<const std::uint8_t*>(props.data()),props.size()),
        View(reinterpret_cast<const std::uint8_t*>(sale.data()),sale.size()));
}
std::int64_t account(Storage& storage,const std::string& user="Owner") {
    return storage.dispatch("accounts.create",{{"username",user},{"password","fixture"}}).at("account").at("role_id").get<std::int64_t>();
}
GameSettlementRequest settle_request(const std::string& match="match") {
    std::array<std::uint32_t,21> levels{};for(std::size_t i=0;i<levels.size();++i)levels[i]=static_cast<std::uint32_t>(i)*50;
    return {match+":result",match,"fixture-stage",GameOutcome::win,0,{},
        {"fixture raw resource pool only",{10,20,0,GameSettlementItemReward{3,{1125,200,1125}}},
            {5,8,0,GameSettlementItemReward{3,{1125,200,1125}}},{0,0,0},{0,0,0},levels,0}};
}
GameSettlementItemInstance instance(std::uint32_t id,std::int64_t expires,GameSettlementItemActivation activation=GameSettlementItemActivation::active,
    RichonlineInventoryDateVersion version=original) {
    const auto base=id|(activation==GameSettlementItemActivation::requires_activation?0x40000000U:0);
    return {richonline_inventory_key_from_expiry(base,expires,version),expires==0?std::nullopt:std::optional<std::int64_t>(expires),activation};
}
GameSettlementItemResolution resolution(const std::string& match="match") {
    return {match+":items",match+":result","fixture-explicit-two-card-one-avatar-v1",
        "Fixture selects pool indexes0 and1, explicit quantities2 and1; explicit expiry/activation, no historical selection claim",original,
        {{0,2,{instance(1125,expiry),instance(1125,expiry+86400)}},
            {1,1,{instance(200,expiry,GameSettlementItemActivation::requires_activation)}}}};
}
Json config(const GameSettlementItemResolution& request) {
    Json selections=Json::array();for(const auto& selected:request.selections) {
        Json items=Json::array();for(const auto& item:selected.instances)items.push_back({{"owned_key",item.owned_key},
            {"expires_at",item.expires_at?Json(*item.expires_at):Json(nullptr)},
            {"activation",item.activation==GameSettlementItemActivation::active?"active":"requires_activation"}});
        selections.push_back({{"resource_index",selected.resource_index},{"quantity",selected.quantity},{"instances",items}});
    }
    return {{"operation_id",request.operation_id},{"settlement_operation",request.settlement_operation},
        {"policy_identifier",request.policy_identifier},{"evidence",request.evidence},
        {"key_date_version",request.key_date_version==original?"original-2005":std::string(richonline_inventory_compatibility_id)},
        {"selections",selections}};
}
}
int main(){try {
    const auto directory=std::filesystem::temp_directory_path()/("settlement-item-resolution-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(directory);
    const auto products=catalog();const auto path=directory/"basic.sqlite3";Storage storage(path);const auto role=account(storage);Database db(path);
    const auto economic=storage.settle_game("Owner",role,settle_request());const auto request=resolution();
    auto parsed=decode_game_settlement_item_resolution(config(request));
    check(parsed.selections[0].quantity==2&&parsed.selections[1].instances[0].activation==GameSettlementItemActivation::requires_activation,
        "typed_config_lost_explicit_quantity_activation");
    auto cfg=config(request);cfg["selections"][0].erase("quantity");
    reject([&]{(void)decode_game_settlement_item_resolution(cfg);},"game_settlement_items_config_shape_invalid");
    cfg=config(request);cfg["selections"][0]["instances"][0].erase("expires_at");
    reject([&]{(void)decode_game_settlement_item_resolution(cfg);},"game_settlement_items_config_shape_invalid");
    cfg=config(request);cfg["surprise"]=1;
    reject([&]{(void)decode_game_settlement_item_resolution(cfg);},"game_settlement_items_config_shape_invalid");
    reject([&]{(void)storage.resolve_game_settlement_items("Other",role,products,request,original_guard,now);},"game_settlement_items_role_not_owned");
    auto bad=request;bad.selections[0].quantity=1;
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_quantity_invalid");
    bad=request;bad.selections[0].instances[1]=bad.selections[0].instances[0];
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_duplicate_key");
    bad=request;bad.selections[0].instances[0].activation=GameSettlementItemActivation::requires_activation;
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_key_state_invalid");
    bad=request;bad.selections[0].instances[0].expires_at.reset();
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_key_date_mismatch");
    bad=request;bad.selections[0].resource_index=7;
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_resource_index_invalid");
    bad=request;bad.selections[0].instances[0]=instance(201,expiry);
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_product_mismatch");
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,request,compat_guard,now);},"inventory_date_database_mode_mismatch");
    auto bad_guard=original_guard;bad_guard.verified_client_compatibility_id="arbitrary-copy";
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,request,bad_guard,now);},"game_settlement_items_client_guard_invalid");
    const auto result=storage.resolve_game_settlement_items("Owner",role,products,parsed,original_guard,now);
    check(result.status==GameSettlementItemResolutionStatus::resolved&&result.items.size()==3&&
        result.items[0].current_owned_key==request.selections[0].instances[0].owned_key&&
        result.items[2].activation==GameSettlementItemActivation::requires_activation,"explicit_grants_not_preserved");
    check(storage.pending_game_settlement_item_rewards("Owner",role).empty()&&storage.lobby_inventory("Owner",role,now).items.size()==3,
        "resolved_intent_not_atomic_authoritative_inventory");
    check(db.scalar("SELECT count(*) FROM audit WHERE source='native-game-item-resolution'")==3,"missing_grant_audit");
    check(storage.settle_game("Owner",role,settle_request()).replayed&&storage.roles_for_username("Owner")[0].at("gold")==economic.gold_after,
        "item_resolution_reapplied_economic_reward");
    Storage reopened(path);check(reopened.resolve_game_settlement_items("Owner",role,products,request,original_guard,now).status==
        GameSettlementItemResolutionStatus::replayed&&db.scalar("SELECT count(*) FROM lobby_inventory")==3,"reopen_replay_duplicate_grant");
    bad=request;bad.evidence+=" changed";
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_operation_conflict");
    bad=request;bad.operation_id="another-resolution";
    reject([&]{(void)storage.resolve_game_settlement_items("Owner",role,products,bad,original_guard,now);},"game_settlement_items_already_resolved");
    db.exec("DELETE FROM lobby_inventory WHERE encoded_item="+std::to_string(request.selections[0].instances[0].owned_key));
    const auto consumed=storage.resolve_game_settlement_items("Owner",role,products,request,original_guard,now);
    check(!consumed.items[0].current_owned_key&&consumed.items[1].current_owned_key&&db.scalar("SELECT count(*) FROM lobby_inventory")==2,
        "replay_restored_consumed_inventory");
    const auto expired=storage.resolve_game_settlement_items("Owner",role,products,request,original_guard,expiry+86401);
    check(std::none_of(expired.items.begin(),expired.items.end(),[](const auto& item){return item.current_owned_key.has_value();}),
        "replay_revived_expired_items");

    const auto rollback_path=directory/"rollback.sqlite3";Storage rollback(rollback_path);const auto rr=account(rollback);Database rd(rollback_path);
    (void)rollback.settle_game("Owner",rr,settle_request());
    rd.exec("CREATE TRIGGER fail_second BEFORE INSERT ON lobby_inventory WHEN NEW.encoded_item="+
        std::to_string(request.selections[0].instances[1].owned_key)+" BEGIN SELECT RAISE(ABORT,'fixture'); END");
    reject([&]{(void)rollback.resolve_game_settlement_items("Owner",rr,products,request,original_guard,now);},"database_constraint_failed");
    check(rd.scalar("SELECT count(*) FROM lobby_inventory")==0&&rd.scalar("SELECT count(*) FROM operations WHERE source='native-game-item-resolution'")==0&&
        rollback.pending_game_settlement_item_rewards("Owner",rr).size()==1,"partial_grant_did_not_roll_back_and_retain_intent");
    rd.exec("DROP TRIGGER fail_second");
    rd.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit WHEN NEW.source='native-game-item-resolution' BEGIN SELECT RAISE(ABORT,'fixture'); END");
    reject([&]{(void)rollback.resolve_game_settlement_items("Owner",rr,products,request,original_guard,now);},"database_constraint_failed");
    check(rd.scalar("SELECT count(*) FROM lobby_inventory")==0&&rollback.pending_game_settlement_item_rewards("Owner",rr).size()==1,
        "audit_failure_lost_inventory_or_intent");rd.exec("DROP TRIGGER fail_audit");
    check(rollback.resolve_game_settlement_items("Owner",rr,products,request,original_guard,now).status==GameSettlementItemResolutionStatus::resolved,
        "failed_grant_not_retryable");

    const auto full_path=directory/"full.sqlite3";Storage full(full_path);const auto fr=account(full);Database fd(full_path);
    (void)full.settle_game("Owner",fr,settle_request());
    for(std::int64_t i=2;i<10;++i) {
        const auto key=instance(1125,expiry+i*86400).owned_key;
        fd.exec("INSERT INTO lobby_inventory VALUES('Owner',"+std::to_string(key)+","+std::to_string(expiry+i*86400)+")");
    }
    check(full.resolve_game_settlement_items("Owner",fr,products,request,original_guard,now).status==GameSettlementItemResolutionStatus::inventory_full&&
        fd.scalar("SELECT count(*) FROM lobby_inventory")==8&&full.pending_game_settlement_item_rewards("Owner",fr).size()==1,
        "capacity_failure_partially_granted_or_dropped_reward");
    fd.exec("DELETE FROM lobby_inventory");fd.exec("INSERT INTO lobby_inventory VALUES('Owner',"+
        std::to_string(request.selections[0].instances[0].owned_key)+","+std::to_string(expiry)+")");
    check(full.resolve_game_settlement_items("Owner",fr,products,request,original_guard,now).status==GameSettlementItemResolutionStatus::inventory_conflict&&
        fd.scalar("SELECT count(*) FROM lobby_inventory")==1&&full.pending_game_settlement_item_rewards("Owner",fr).size()==1,
        "duplicate_ownership_overwritten_or_merged");

    const auto modern_path=directory/"modern.sqlite3";Storage modern(modern_path);const auto mr=account(modern);Database md(modern_path);
    (void)modern.settle_game("Owner",mr,settle_request());md.exec("INSERT INTO metadata VALUES('inventory_date_version','richonline-inventory-date-2021-v1')");
    auto modern_request=request;modern_request.key_date_version=compat;
    const std::int64_t modern_now=1790000000,modern_expiry=modern_now+365*86400;
    modern_request.selections[0].instances={instance(1125,modern_expiry,GameSettlementItemActivation::active,compat),
        instance(1125,modern_expiry+86400,GameSettlementItemActivation::active,compat)};
    modern_request.selections[1].instances={instance(200,modern_now+86400,GameSettlementItemActivation::requires_activation,compat)};
    reject([&]{(void)modern.resolve_game_settlement_items("Owner",mr,products,modern_request,original_guard,modern_now);},"inventory_date_database_mode_mismatch");
    check(modern.resolve_game_settlement_items("Owner",mr,products,modern_request,compat_guard,modern_now).status==GameSettlementItemResolutionStatus::resolved&&
        modern.lobby_inventory("Owner",mr,modern_now).items.size()==3,"real_2026_expiry_compat_grant_failed");
    reject([&]{(void)instance(1125,modern_expiry);},"inventory_date_year_unrepresentable");
    md.exec("UPDATE operations SET result='{}' WHERE source='native-game-item-resolution'");
    reject([&]{(void)modern.resolve_game_settlement_items("Owner",mr,products,modern_request,compat_guard,modern_now);},"game_settlement_items_operation_conflict");
    reject([&]{(void)modern.pending_game_settlement_item_rewards("Owner",mr);},"game_settlement_resolved_item_reward_invalid");

    const auto race_path=directory/"race.sqlite3";Storage race(race_path);const auto race_role=account(race);
    (void)race.settle_game("Owner",race_role,settle_request());Storage race_peer(race_path);std::latch start(1);
    auto worker=[&](Storage& target){start.wait();return target.resolve_game_settlement_items("Owner",race_role,products,request,original_guard,now).status;};
    auto left=std::async(std::launch::async,worker,std::ref(race));
    auto right=std::async(std::launch::async,worker,std::ref(race_peer));start.count_down();
    const auto a=left.get(),b=right.get();
    check((a==GameSettlementItemResolutionStatus::resolved&&b==GameSettlementItemResolutionStatus::replayed)||
        (b==GameSettlementItemResolutionStatus::resolved&&a==GameSettlementItemResolutionStatus::replayed),"concurrent_exact_resolution_not_serialized");
    Database race_db(race_path);check(race_db.scalar("SELECT count(*) FROM lobby_inventory")==3&&
        race_db.scalar("SELECT count(*) FROM game_settlement_item_resolutions")==1,"concurrent_resolution_duplicated_grant");
    std::cout<<"PASS explicit item resolution: typed policy, per-unit keys/expiry/activation, atomic rollback, durable intent, capacity/conflict, replay, epochs\n";
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
