#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class F>void rejected(F fn,const char* code) {
    try{fn();}catch(const StorageError& error){check(std::string(error.what())==code,"wrong_rejection");return;}
    throw std::runtime_error("missing_rejection");
}
void sql(const std::filesystem::path& path,const char* statement) {
    sqlite3* db=nullptr;const auto name=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture_open");
    const auto result=sqlite3_exec(db,statement,nullptr,nullptr,nullptr);sqlite3_close(db);check(result==SQLITE_OK,"fixture_sql");
}
GameSettlementRequest request(const std::string& match="match") {
    std::array<std::uint32_t,21> levels{};
    for(std::size_t i=0;i<levels.size();++i)levels[i]=static_cast<std::uint32_t>(i)*100;
    return {match+":settlement",match,"test-stage",GameOutcome::win,0,std::nullopt,
        {"explicit isolated test policy",{10,20,3},{5,8,1},{2,0,0},{3,4,0},levels,0},
        GameSettlementDelivery{1,2,0,0,7,true,{}}};
}
void u32(std::array<std::uint8_t,144>& bytes,std::size_t offset,std::uint32_t value) {
    for(std::size_t i=0;i<4;++i)bytes[offset+i]=static_cast<std::uint8_t>(value>>static_cast<unsigned>(i*8));
}
void f64(std::array<std::uint8_t,144>& bytes,std::size_t offset,double value) {
    const auto raw=std::bit_cast<std::uint64_t>(value);
    for(std::size_t i=0;i<8;++i)bytes[offset+i]=static_cast<std::uint8_t>(raw>>static_cast<unsigned>(i*8));
}
struct Fixture {
    std::filesystem::path path;Storage storage;std::int64_t role;
    static constexpr std::uint32_t wire_actor=0x12345678U;
    explicit Fixture(std::filesystem::path file):path(std::move(file)),storage(path),
        role(storage.dispatch("accounts.create",{{"username","owner"},{"password","isolated"}}).at("account").at("role_id").get<std::int64_t>()) {
        sql(path,"UPDATE roles SET gold=100,coins=250,bank=300,level=0,experience=45,wins=0,losses=0,draws=0");
    }
    std::array<std::uint8_t,144> snapshot() {
        const auto current=storage.roles_for_username("owner").at(0);std::array<std::uint8_t,144> bytes{};
        u32(bytes,0,wire_actor);u32(bytes,4,1);u32(bytes,12,2);u32(bytes,44,0);
        for(const auto& [offset,key]:std::array<std::pair<std::size_t,const char*>,7>{{
            {24,"wins"},{28,"losses"},{32,"draws"},{40,"model"},{52,"level"},{104,"experience"},{108,"escapes"}}})
            u32(bytes,offset,current.at(key).get<std::uint32_t>());
        f64(bytes,80,current.at("coins").get<double>());f64(bytes,88,current.at("gold").get<double>());
        f64(bytes,96,current.at("bank").get<double>());bytes[112]='x';u32(bytes,40,0x54321U);
        // Exercise preserved fields that are not derived from settlement.
        u32(bytes,56,0xdeadbeefU);u32(bytes,76,0xaabbccddU);return bytes;
    }
    void terminal(const GameSettlementRequest& q) {
        for(std::uint32_t i=0;i<3;++i)storage.advance_game_settlement_outbox("owner",role,q.operation_id,i);
    }
};
void lifecycle(const std::filesystem::path& path) {
    Fixture f(path);const auto q=request();const auto settled=f.storage.settle_game("owner",f.role,q);
    check(f.storage.pending_game_settlement_profile_refreshes("owner",f.role).empty(),"intent_before_terminal58");
    auto bytes=f.snapshot();
    rejected([&]{f.storage.stage_game_settlement_profile_refresh("owner",f.role,q.operation_id,Fixture::wire_actor,"first",bytes);},
        "game_settlement_refresh_lobby_not_delivered");
    f.storage.advance_game_settlement_outbox("owner",f.role,q.operation_id,0);
    f.storage.advance_game_settlement_outbox("owner",f.role,q.operation_id,1);
    check(f.storage.pending_game_settlement_profile_refreshes("owner",f.role).empty(),"intent_before_exact58");
    f.storage.advance_game_settlement_outbox("owner",f.role,q.operation_id,2);
    Storage reopened(path);const auto pending=reopened.pending_game_settlement_profile_refreshes("owner",f.role);
    check(pending.size()==1 && pending[0].match_id==q.match_id && pending[0].role_id==f.role,"durable_intent_missing");
    auto first=f.storage.stage_game_settlement_profile_refresh("owner",f.role,q.operation_id,Fixture::wire_actor,"first",bytes);
    check(first.attempt==1 && first.profile==bytes,"snapshot_modified");
    check(!f.storage.confirm_game_settlement_profile_refresh("owner",f.role,first,7,bytes),"wrong_wire_confirmed");
    check(!f.storage.confirm_game_settlement_profile_refresh("owner",f.role,first,19,std::span(bytes).first(143)),"partial_confirmed");
    auto wrong=bytes;wrong[76]^=1;
    check(!f.storage.confirm_game_settlement_profile_refresh("owner",f.role,first,19,wrong),"different_exact_bytes_confirmed");
    auto second=reopened.stage_game_settlement_profile_refresh("owner",f.role,q.operation_id,Fixture::wire_actor,"second",bytes);
    check(second.attempt==2 && !f.storage.confirm_game_settlement_profile_refresh("owner",f.role,first,19,bytes),"stale_transport_callback_confirmed");
    auto forged=second;forged.intent.match_id="other";
    check(!f.storage.confirm_game_settlement_profile_refresh("owner",f.role,forged,19,bytes),"wrong_match_confirmed");
    check(f.storage.confirm_game_settlement_profile_refresh("owner",f.role,second,19,bytes),"exact_current_attempt_not_confirmed");
    check(!reopened.confirm_game_settlement_profile_refresh("owner",f.role,second,19,bytes),"duplicate_confirmed");
    check(reopened.pending_game_settlement_profile_refreshes("owner",f.role).empty(),"confirmed_intent_pending");
    rejected([&]{f.storage.stage_game_settlement_profile_refresh("owner",f.role,q.operation_id,Fixture::wire_actor,"third",bytes);},
        "game_settlement_refresh_already_delivered");
    check(f.storage.settle_game("owner",f.role,q).replayed,"settlement_replay_failed");
    check(f.storage.roles_for_username("owner").at(0).at("gold")==settled.gold_after,"refresh_reawarded_settlement");
    check(f.storage.pending_game_settlement_profile_refreshes("owner",f.role).empty(),"replay_recreated_intent");
}
void validation(const std::filesystem::path& path) {
    Fixture f(path);const auto q=request();(void)f.storage.settle_game("owner",f.role,q);f.terminal(q);
    const auto bytes=f.snapshot();auto stage=[&](std::span<const std::uint8_t> value) {
        return f.storage.stage_game_settlement_profile_refresh("owner",f.role,q.operation_id,Fixture::wire_actor,"generation",value);
    };
    rejected([&]{stage(std::span(bytes).first(143));},"game_settlement_refresh_profile_invalid");
    auto invalid=bytes;u32(invalid,0,Fixture::wire_actor+1);
    rejected([&]{stage(invalid);},"game_settlement_refresh_profile_invalid");
    invalid=bytes;std::fill(invalid.begin()+112,invalid.end(),std::uint8_t{1});
    rejected([&]{stage(invalid);},"game_settlement_refresh_profile_invalid");
    invalid=bytes;f64(invalid,88,std::numeric_limits<double>::quiet_NaN());
    rejected([&]{stage(invalid);},"game_settlement_refresh_profile_invalid");
    sql(path,"UPDATE roles SET gold=77,coins=91,escapes=2");
    rejected([&]{stage(bytes);},"game_settlement_refresh_profile_stale");
    const auto fresh=f.snapshot();const auto attempt=stage(fresh);
    check(attempt.profile==fresh && attempt.profile!=bytes,"historical_settlement_values_used");
    rejected([&]{f.storage.stage_game_settlement_profile_refresh("wrong",f.role,q.operation_id,Fixture::wire_actor,"generation",fresh);},
        "game_settlement_role_not_owned");
}
void atomic_intent(const std::filesystem::path& path) {
    Fixture f(path);check(f.storage.pending_game_settlement_profile_refreshes("owner",f.role).empty(),"unexpected_intent");
    sql(path,"CREATE TRIGGER fail_refresh BEFORE INSERT ON game_settlement_profile_refreshes BEGIN SELECT RAISE(ABORT,'fixture'); END");
    bool failed=false;try{(void)f.storage.settle_game("owner",f.role,request());}catch(const StorageError&){failed=true;}
    check(failed,"intent_rollback_not_injected");const auto current=f.storage.roles_for_username("owner").at(0);
    check(current.at("gold")==100 && current.at("experience")==45 && current.at("wins")==0,"partial_award_committed");
    check(f.storage.pending_game_settlements("owner",f.role).empty(),"partial_outbox_committed");
    sql(path,"DROP TRIGGER fail_refresh");const auto q=request();
    check(!f.storage.settle_game("owner",f.role,q).replayed,"partial_operation_committed");f.terminal(q);
    check(f.storage.pending_game_settlement_profile_refreshes("owner",f.role).size()==1,"retry_intent_missing");
    auto no_delivery=request("abandoned");no_delivery.delivery.reset();
    (void)f.storage.settle_game("owner",f.role,no_delivery);
    check(f.storage.pending_game_settlement_profile_refreshes("owner",f.role).size()==1,"no58_intent_created");
}
void delivery_checkpoint_failure(const std::filesystem::path& path) {
    Fixture f(path);const auto q=request();(void)f.storage.settle_game("owner",f.role,q);f.terminal(q);
    const auto bytes=f.snapshot();const auto first=f.storage.stage_game_settlement_profile_refresh(
        "owner",f.role,q.operation_id,Fixture::wire_actor,"same-generation",bytes);
    sql(path,"CREATE TRIGGER fail_refresh_confirm BEFORE UPDATE OF state ON game_settlement_profile_refreshes BEGIN SELECT RAISE(ABORT,'fixture'); END");
    bool failed=false;try{(void)f.storage.confirm_game_settlement_profile_refresh("owner",f.role,first,19,bytes);}
    catch(const StorageError&){failed=true;}
    check(failed,"checkpoint_failure_missing");Storage reopened(path);
    check(reopened.pending_game_settlement_profile_refreshes("owner",f.role).size()==1,"checkpoint_failure_lost_intent");
    sql(path,"DROP TRIGGER fail_refresh_confirm");const auto retry=reopened.stage_game_settlement_profile_refresh(
        "owner",f.role,q.operation_id,Fixture::wire_actor,"same-generation",bytes);
    check(retry.attempt==first.attempt+1 &&
        !f.storage.confirm_game_settlement_profile_refresh("owner",f.role,first,19,bytes),"same_generation_old_callback_confirmed");
    check(reopened.confirm_game_settlement_profile_refresh("owner",f.role,retry,19,bytes),"checkpoint_retry_failed");
}
}
int main() {
    try {
        const auto root=std::filesystem::temp_directory_path()/
            ("postgame-refresh-tests-"+std::to_string(GetCurrentProcessId())+"-"+
             std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root);
        lifecycle(root/"lifecycle.sqlite");validation(root/"validation.sqlite");atomic_intent(root/"atomic.sqlite");
        delivery_checkpoint_failure(root/"checkpoint.sqlite");
        std::filesystem::remove_all(root);std::cout<<"game settlement profile refresh tests PASS\n";
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
