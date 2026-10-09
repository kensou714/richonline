#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <future>
#include <iostream>
#include <limits>
#include <memory>
#include <vector>

namespace {
using namespace richnet;
void check(bool result,const char* reason){if(!result)throw std::runtime_error(reason);}
class Database {
public:
    explicit Database(const std::filesystem::path& path) {
        const auto name=path.u8string();check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture open");
    }
    ~Database(){sqlite3_close(db);}
    void exec(const char* command){check(sqlite3_exec(db,command,nullptr,nullptr,nullptr)==SQLITE_OK,"fixture SQL");}
    int count(const char* command){sqlite3_stmt* statement=nullptr;
        check(sqlite3_prepare_v2(db,command,-1,&statement,nullptr)==SQLITE_OK,"fixture prepare");
        check(sqlite3_step(statement)==SQLITE_ROW,"fixture count");const auto n=sqlite3_column_int(statement,0);
        sqlite3_finalize(statement);return n;}
private:sqlite3* db{};
};
template<class Action>void rejected(Action action,const std::string& code) {
    try{action();}catch(const StorageError& error){check(error.what()==code,"unexpected rejection");return;}
    throw std::runtime_error("expected rejection missing");
}
struct Fixture {
    std::filesystem::path path;Storage storage;std::int64_t actor;
    explicit Fixture(const std::filesystem::path& file):path(file),storage(file),
        actor(storage.dispatch("accounts.create",{{"username","charge-owner"},{"password","isolated"}}).at("account").at("role_id").get<std::int64_t>()) {
        Database(path).exec("UPDATE roles SET gold=100,coins=250,bank=300");
    }
    GameGoldChargeResult charge(double value,std::string operation="game-001:action-001",std::string reason="paid controlled die") {
        return storage.consume_game_gold("charge-owner",actor,{value,std::move(operation),std::move(reason)});
    }
    void balance(double value){const auto role=storage.roles_for_username("charge-owner").at(0);
        check(role["gold"]==value && role["coins"]==250 && role["bank"]==300,"wrong persistent ledger");}
};
void basic(const std::filesystem::path& path) {
    Fixture f(path);const auto account=f.storage.game_account_for_role(f.actor);
    check(account.username=="charge-owner" && account.gold==100,"trusted account snapshot");
    rejected([&]{f.storage.game_account_for_role(-1);},"game_charge_role_missing");
    auto a=f.charge(2.5);check(a.status==GameChargeStatus::success && !a.replayed && a.gold_after==97.5,"charge result");
    auto b=f.charge(2.5);check(b.status==GameChargeStatus::success && b.replayed && b.gold_after==97.5,"replay result");
    check(f.charge(7.5,"game-001:action-002").status==GameChargeStatus::success,"second operation");
    b=f.charge(2.5);check(b.replayed && b.gold_after==97.5,"replay historical result");f.balance(90);
    rejected([&]{f.charge(3);},"game_charge_operation_conflict");
    rejected([&]{f.charge(2.5,"game-001:action-001","shop refresh");},"game_charge_operation_conflict");
    auto fail=f.charge(91,"insufficient");check(fail.status==GameChargeStatus::insufficient_funds && !fail.replayed,"insufficient");
    Database(path).exec("UPDATE roles SET gold=200");
    fail=f.charge(91,"insufficient");check(fail.status==GameChargeStatus::insufficient_funds && fail.replayed,"rejected idempotent retry cannot later debit");f.balance(200);
    for(double n:{0.0,-1.0,std::numeric_limits<double>::quiet_NaN(),std::numeric_limits<double>::infinity()})
        check(f.charge(n,"invalid").status==GameChargeStatus::invalid_amount,"invalid amount");
    rejected([&]{f.charge(1,"");},"game_charge_operation_id_invalid");
    rejected([&]{f.charge(1,"bad-reason","");},"game_charge_reason_invalid");
    rejected([&]{f.storage.consume_game_gold("another-owner",f.actor,{0,"identity","test"});},"game_charge_role_not_owned");
    const auto other=f.storage.dispatch("accounts.create",{{"username","other"},{"password","isolated"}}).at("account").at("role_id").get<std::int64_t>();
    rejected([&]{f.storage.consume_game_gold("other",other,{2.5,"game-001:action-001","paid controlled die"});},"game_charge_operation_conflict");
    Database db(path);check(db.count("SELECT count(*) FROM audit WHERE source='native-game-charge'")==2,"one audit per committed charge");
    check(db.count("SELECT count(*) FROM operations WHERE source='native-game-charge'")==3,"success and funds refusal persisted");
    Storage reopened(path);const auto replay=reopened.consume_game_gold("charge-owner",f.actor,{2.5,"game-001:action-001","paid controlled die"});
    check(replay.replayed && replay.gold_after==97.5,"persistent idempotency");
}
void rollback(const std::filesystem::path& path) {
    Fixture f(path);Database db(path);
    for(const auto* table:{"audit","operations"}) {
        const auto command=std::string("CREATE TRIGGER reject_charge BEFORE INSERT ON ")+table+
            " WHEN NEW.source='native-game-charge' BEGIN SELECT RAISE(ABORT,'charge_fixture'); END";
        db.exec(command.c_str());bool failed=false;
        try{f.charge(5);}catch(const StorageError&){failed=true;}
        check(failed,"injected write did not fail");f.balance(100);
        check(db.count("SELECT count(*) FROM audit WHERE source='native-game-charge'")==0 &&
            db.count("SELECT count(*) FROM operations")==0,"partial charge escaped rollback");
        db.exec("DROP TRIGGER reject_charge");
    }
    check(f.charge(5).status==GameChargeStatus::success,"retry after rollback");f.balance(95);
    db.exec("UPDATE roles SET gold=9007199254740992");
    check(f.charge(0.5,"precision").status==GameChargeStatus::invalid_amount,"rounded charge rejected");
}
void concurrency(const std::filesystem::path& path,bool same_operation) {
    Fixture f(path);std::vector<std::unique_ptr<Storage>> writers;
    for(int i=0;i<8;++i)writers.push_back(std::make_unique<Storage>(path));
    std::promise<void> start;const auto ready=start.get_future().share();std::vector<std::future<GameGoldChargeResult>> replies;
    for(std::size_t i=0;i<writers.size();++i)replies.push_back(std::async(std::launch::async,[&,i]{
        ready.wait();return writers[i]->consume_game_gold("charge-owner",f.actor,{25,same_operation?"same":std::to_string(i),"concurrent"});}));
    start.set_value();int fresh=0,replayed=0,insufficient=0;
    for(auto& reply:replies){check(reply.wait_for(std::chrono::seconds(10))==std::future_status::ready,"concurrent timeout");const auto result=reply.get();
        fresh+=result.status==GameChargeStatus::success && !result.replayed;replayed+=result.replayed;
        insufficient+=result.status==GameChargeStatus::insufficient_funds;}
    check(fresh==(same_operation?1:4) && replayed==(same_operation?7:0) && insufficient==(same_operation?0:4),"concurrent conservation/idempotency");
    f.balance(same_operation?75:0);
}
}
int main(){try{
    const auto root=std::filesystem::temp_directory_path()/("game-charge-tests-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));std::filesystem::create_directories(root);
    basic(root/"basic.sqlite3");rollback(root/"rollback.sqlite3");
    Storage original(root/"original.sqlite3",ClientProfile::original);
    rejected([&]{original.game_account_for_role(1);},"game_charge_profile_invalid");
    concurrency(root/"same.sqlite3",true);concurrency(root/"distinct.sqlite3",false);
    std::cout<<"PASS game gold charge identity, precision, replay, SQLite rollback and concurrent conservation\n";
}catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}}
