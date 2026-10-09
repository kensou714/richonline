#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* error){if(!value)throw std::runtime_error(error);}
template<class F> void rejected(F fn,const char* expected) {
    try {fn();}catch(const StorageError& error){check(std::string(error.what())==expected,"unexpected_rejection");return;}
    throw std::runtime_error("missing_rejection");
}
class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        const auto name=path.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db_)==SQLITE_OK,"fixture_open");
    }
    ~Database(){sqlite3_close(db_);}
    void exec(const char* command){check(sqlite3_exec(db_,command,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture_sql");}
    std::int64_t count(const char* command) {
        sqlite3_stmt* statement=nullptr;
        check(sqlite3_prepare_v2(db_,command,-1,&statement,nullptr)==SQLITE_OK,"fixture_prepare");
        check(sqlite3_step(statement)==SQLITE_ROW,"fixture_scalar");
        const auto result=sqlite3_column_int64(statement,0);sqlite3_finalize(statement);return result;
    }
private:
    sqlite3* db_{};
};
GameSettlementRequest request(const std::string& match,GameOutcome outcome=GameOutcome::win) {
    std::array<std::uint32_t,21> levels{};
    for(std::size_t i=0;i<levels.size();++i)levels[i]=static_cast<std::uint32_t>(i)*50;
    return {match+":result",match,"resource-stage",outcome,0,{},
        {"fixture only; resource lists are unresolved item specifications",
            {10,20,0,GameSettlementItemReward{2,{1125,1125}}},
            {5,8,0,GameSettlementItemReward{3,{4,200,201}}},
            {0,0,0},{0,0,0},levels,0}};
}
}
int main(){try {
    using namespace richnet;
    const auto directory=std::filesystem::temp_directory_path()/("settlement-item-test-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(directory);
    const auto path=directory/"items.sqlite3";Storage storage(path);
    const auto role=storage.dispatch("accounts.create",{{"username","item-owner"},{"password","fixture"}}).at("account").at("role_id").get<std::int64_t>();
    Database db(path);db.exec("UPDATE roles SET gold=100,level=0,experience=0,wins=0,losses=0,draws=0");
    const auto inventory_before=storage.lobby_inventory("item-owner",role,1900000000).items;
    check(storage.pending_game_settlement_item_rewards("item-owner",role).empty(),"fresh_no_pending_item_reward");
    auto first=request("first");
    const auto receipt=storage.settle_game("item-owner",role,first);
    check(receipt.first_clear && receipt.reward.items==first.policy.first_win.items,"first_resource_specification_selected");
    auto pending=storage.pending_game_settlement_item_rewards("item-owner",role);
    check(pending.size()==1 && pending[0].operation_id==first.operation_id && pending[0].match_id==first.match_id &&
        pending[0].stage_key==first.stage_key && pending[0].specification.resource_ids==std::vector<std::int32_t>{1125,1125},
        "durable_resource_ids_keep_multiplicity_and_identity");
    check(storage.settle_game("item-owner",role,first).replayed &&
        storage.pending_game_settlement_item_rewards("item-owner",role).size()==1,"exact_replay_no_duplicate_pending_reward");
    auto changed=first;changed.policy.first_win.items->resource_ids[0]=1072;
    rejected([&]{(void)storage.settle_game("item-owner",role,changed);},"game_settlement_operation_conflict");
    changed=request("invalid-count");changed.policy.first_win.items->resource_count=3;
    rejected([&]{(void)storage.settle_game("item-owner",role,changed);},"game_settlement_item_reward_invalid");
    rejected([&]{(void)storage.pending_game_settlement_item_rewards("another-user",role);},"game_pledge_role_not_owned");
    auto second=request("repeat");
    const auto repeated=storage.settle_game("item-owner",role,second);
    check(!repeated.first_clear && repeated.reward.items==second.policy.repeat_win.items,"repeat_resource_specification_selected");
    auto empty=request("empty");empty.stage_key="empty-stage";
    empty.policy.first_win.items.reset();empty.policy.repeat_win.items.reset();
    check(!storage.settle_game("item-owner",role,empty).reward.items,"empty_item_policy_uses_no_specification");
    check(db.count("SELECT instr(request,'\"items\"')+instr(result,'\"items\"') FROM operations WHERE operation_id='empty:result'")==0,
        "historical_empty_item_json_shape_unchanged");
    (void)storage.settle_game("item-owner",role,request("loss",GameOutcome::loss));
    pending=storage.pending_game_settlement_item_rewards("item-owner",role);
    check(pending.size()==2 && pending[1].specification.resource_count==3 &&
        pending[1].specification.resource_ids==std::vector<std::int32_t>{4,200,201},"loss_no_implicit_item_reward");
    Storage reopened(path);
    check(reopened.pending_game_settlement_item_rewards("item-owner",role).size()==2,"pending_reward_survives_reopen");
    check(db.count("SELECT count(*) FROM game_settlement_item_rewards WHERE state='unresolved'")==2,"not_falsely_marked_inventory_granted");
    check(storage.lobby_inventory("item-owner",role,1900000000).items==inventory_before,"no_fabricated_owned_key");

    const auto rollback_path=directory/"rollback.sqlite3";Storage rollback(rollback_path);
    const auto rollback_role=rollback.dispatch("accounts.create",{{"username","item-owner"},{"password","fixture"}}).at("account").at("role_id").get<std::int64_t>();
    Database rollback_db(rollback_path);rollback_db.exec("UPDATE roles SET gold=100,experience=0,wins=0");
    (void)rollback.pending_game_settlement_item_rewards("item-owner",rollback_role);
    rollback_db.exec("CREATE TRIGGER reject_item BEFORE INSERT ON game_settlement_item_rewards BEGIN SELECT RAISE(ABORT,'fixture'); END");
    bool failed=false;try{(void)rollback.settle_game("item-owner",rollback_role,request("atomic"));}catch(const StorageError&){failed=true;}
    check(failed,"item_insert_failure_injected");
    const auto row=rollback.roles_for_username("item-owner").at(0);
    check(row.at("gold")==100 && row.at("experience")==0 && row.at("wins")==0,"item_failure_rolls_back_account_award");
    check(rollback_db.count("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='game_stage_progress'")==0 &&
        rollback_db.count("SELECT count(*) FROM operations WHERE source='native-game-settlement'")==0,
        "item_failure_rolls_back_first_clear_and_receipt");
    rollback_db.exec("DROP TRIGGER reject_item");
    check(rollback.settle_game("item-owner",rollback_role,request("atomic")).first_clear,"retry_retains_first_clear_reward");
    std::cout<<"PASS pending resource item rewards: atomic, replay safe, owner bound, ordered, recoverable; no inventory grant claim\n";
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
