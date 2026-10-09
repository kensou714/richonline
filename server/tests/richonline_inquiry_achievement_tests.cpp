#include "richonline_ranking.hpp"
#include "richonline_game_ledger.hpp"
#include "storage.hpp"
#include <windows.h>
#include <algorithm>
#include <bit>
#include <chrono>
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F>void rejects(F action,const char* expected) {
    try{action();}catch(const std::runtime_error& error){check(std::string(error.what())==expected,error.what());return;}
    throw std::runtime_error("expected rejection absent");
}
Bytes query(std::uint32_t type,std::int32_t category,std::string_view name) {
    Bytes value{13,10};append_le(value,type,4);append_le(value,static_cast<std::uint32_t>(category),4);
    const auto bytes=richonline_auxiliary_name(name);value.insert(value.end(),bytes.begin(),bytes.end());return value;
}
std::int32_t i32(const Bytes& response,std::size_t offset){return std::bit_cast<std::int32_t>(read_le(View(response).subspan(offset,4)));}
std::string name(const Bytes& response,std::size_t offset) {
    const auto first=response.begin()+static_cast<std::ptrdiff_t>(offset);
    return {first,std::find(first,first+32,0)};
}
void settle(Storage& accounts,const std::string& username,std::int64_t role,const std::string& match) {
    std::array<std::uint32_t,21> levels{};
    for(std::size_t i=0;i<levels.size();++i)levels[i]=static_cast<std::uint32_t>(i)*100;
    const GameSettlementReward reward{0,0,0,{}};
    accounts.settle_game(username,role,{match+":"+std::to_string(role),match,"inquiry-test",GameOutcome::win,0,{},
        {"isolated zero-economics test settlement",reward,reward,reward,reward,levels,0},{}});
}
std::uint64_t ledger_income() {
    RichonlineGameLedger ledger({{1000,500,20,100},{1000,500,20,100}});
    check(ledger.earned_cash(0)==0,"initial funds counted as earned");
    ledger.adjust(0,ledger.snapshot(0),{-100,100,0,0});
    ledger.adjust(0,ledger.snapshot(0),{100,-100,0,0});
    ledger.adjust(0,ledger.snapshot(0),{0,0,10,5});
    check(ledger.earned_cash(0)==0,"transfer or non-board currency counted");
    ledger.adjust(0,ledger.snapshot(0),{-100,0,0,0});
    const auto before=ledger.snapshot(0);
    ledger.adjust(0,before,{200,0,0,0});
    check(ledger.earned_cash(0)==200,"positive income not counted");
    rejects([&]{ledger.adjust(0,before,{200,0,0,0});},"richonline_game_ledger_conflict");
    auto first=ledger.snapshot(0),second=ledger.snapshot(1);
    auto f=first.funds,s=second.funds;f.cash-=50;s.cash+=50;
    const std::array<RichonlineGameFundsUpdate,2> updates{{{0,first,f},{1,second,s}}};
    check(!ledger.commit_batch(updates,[]{return false;}),"declined batch committed");
    rejects([&]{ledger.commit_batch(updates,[]()->bool{throw CodecError("test authorizer failure");});},"test authorizer failure");
    check(ledger.earned_cash(0)==200&&ledger.earned_cash(1)==0,"failed batch counted");
    check(ledger.commit_batch(updates,[]{return true;}),"batch did not commit");
    check(ledger.earned_cash(0)==200&&ledger.earned_cash(1)==50,"batch recipient not counted exactly once");
    ledger.adjust(0,ledger.snapshot(0),{0,25,0,0});
    check(ledger.earned_cash(0)==225,"deposit interest not counted");
    ledger.consume_reserve(0,10,[]{return true;});
    check(ledger.earned_cash(0)==225,"reserve debit changed income");
    RichonlineGameLedger unknown({{100,{},0,{}}});
    rejects([&]{unknown.earned_cash(0);},"richonline_game_ledger_earned_cash_unavailable");
    rejects([&]{ledger.earned_cash(2);},"richonline_game_ledger_actor_invalid");
    return ledger.earned_cash(0);
}
void ranking(const std::filesystem::path& path,std::uint64_t earned) {
    Storage accounts(path);
    const auto add=[&](const std::string& username){return accounts.dispatch("accounts.create",{{"username",username},{"password","test"}})
        .at("account").at("role_id").get<std::int64_t>();};
    const auto alice=add("Alice"),bob=add("Bob"),zero=add("Zero");
    RichonlineRankingStore ranks(path);
    rejects([&]{ranks.response(query(0,3,"Alice"));},"ranking_achievement_statistics_not_integrated");
    RichonlineAchievementStore achievements(path);
    rejects([&]{ranks.response(query(0,3,"Alice"));},"ranking_achievement_category_not_recorded");
    rejects([&]{achievements.record_match("Alice",alice,"unsettled",RichonlineAchievement::cash_earned,earned,richonline_cash_earned_policy);},"ranking_achievement_match_not_settled");
    settle(accounts,"Alice",alice,"match-a");settle(accounts,"Bob",bob,"match-b");settle(accounts,"Zero",zero,"match-zero");
    check(achievements.record_match("Alice",alice,"match-a",RichonlineAchievement::cash_earned,earned,richonline_cash_earned_policy),"first observation absent");
    check(!achievements.record_match("Alice",alice,"match-a",RichonlineAchievement::cash_earned,earned,richonline_cash_earned_policy),"retry double-counted");
    achievements.record_match("Bob",bob,"match-b",RichonlineAchievement::cash_earned,earned,richonline_cash_earned_policy);
    achievements.record_match("Zero",zero,"match-zero",RichonlineAchievement::cash_earned,0,richonline_cash_earned_policy);
    auto response=*ranks.response(query(0,3,"Bob"));
    check(response.size()==124&&i32(response,0)==0&&i32(response,4)==116,"type0 response framing");
    check(i32(response,8)==2&&name(response,12)=="Bob"&&i32(response,44)==225,"own rank/value layout");
    check(i32(response,48)==2&&name(response,52)=="Alice"&&name(response,88)=="Bob","top rows/tie order");
    check(i32(*ranks.response(query(2,3,"Bob")),8)==2,"exact rank search");
    check(i32(*ranks.response(query(2,3,"bob")),8)==-1,"search lost case");
    check(i32(*ranks.response(query(2,3,"Nobody")),8)==-1,"absent name success");
    check(i32(*ranks.response(query(2,3,"Zero")),8)==-1,"zero income got ranked");
    auto missing=*ranks.response(query(0,3,"Nobody"));
    check(i32(missing,8)==-1&&i32(missing,44)==0&&name(missing,12)=="Nobody","unranked own record sentinel");
    const auto request=query(0,3,"Alice");
    for(std::size_t size=0;size<request.size();++size)check(!ranks.response(View(request).first(size)),"fragment was consumed early");
    rejects([&]{ranks.response(query(0,9,"Alice"));},"ranking_achievement_category_not_recorded");
    rejects([&]{ranks.response(query(2,2,"Alice"));},"ranking_category_unknown");
    rejects([&]{achievements.record_match("Bob",alice,"match-a",RichonlineAchievement::cash_earned,earned,richonline_cash_earned_policy);},"ranking_achievement_role_not_owned");
    rejects([&]{achievements.record_match("Alice",alice,"match-a",RichonlineAchievement::cash_earned,earned+1,richonline_cash_earned_policy);},"ranking_achievement_replay_conflict");
    rejects([&]{achievements.record_match("Alice",alice,"match-a",RichonlineAchievement::cash_earned,earned,"different metric");},"ranking_achievement_policy_conflict");
    settle(accounts,"Bob",bob,"match-b2");
    achievements.record_match("Bob",bob,"match-b2",RichonlineAchievement::cash_earned,10,richonline_cash_earned_policy);
    check(i32(*ranks.response(query(2,3,"Bob")),8)==1,"next committed match not visible");
    check(i32(*ranks.response(query(0,3,"Bob")),44)==235,"matches not summed");
    settle(accounts,"Alice",alice,"overflow");
    rejects([&]{achievements.record_match("Alice",alice,"overflow",RichonlineAchievement::cash_earned,2147483647,richonline_cash_earned_policy);},"ranking_achievement_score_out_of_wire_range");
    RichonlineRankingStore reopened(path);
    check(i32(*reopened.response(query(0,3,"Alice")),44)==225,"failed update changed persistent total");
    for(int i=0;i<102;++i) {
        const auto username="Rank"+std::to_string(i);const auto role=add(username);settle(accounts,username,role,username);
        achievements.record_match(username,role,username,RichonlineAchievement::cash_earned,1000,richonline_cash_earned_policy);
    }
    response=*ranks.response(query(0,3,"Alice"));
    check(response.size()==3652&&i32(response,48)==100&&i32(response,8)==104&&i32(response,44)==225,"top100 truncated own result");
    check(i32(*ranks.response(query(2,3,"Alice")),8)==104,"search outside visible top100");
}
}
int main(){try{
    const auto path=std::filesystem::absolute("inquiry-achievement-"+std::to_string(GetCurrentProcessId())+"-"+
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    ranking(path,ledger_income());
    std::cout<<"PASS NEW inquiry 0/2 settled SQLite metrics, real ledger income, replay, ownership, policy isolation, bounds, top100 and name search\n";
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
