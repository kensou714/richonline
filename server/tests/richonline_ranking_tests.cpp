#include "richonline_ranking.hpp"
#include "storage.hpp"
#include <windows.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool yes,const char* reason){if(!yes)throw std::runtime_error(reason);}
template<class Action>void rejects(Action action,const char* reason){try{action();}catch(const std::runtime_error& error){check(std::string(error.what())==reason,"wrong ranking rejection");return;}throw std::runtime_error("missing ranking rejection");}
Bytes query(std::int32_t category){Bytes b{13,10};append_le(b,1,4);append_le(b,static_cast<std::uint32_t>(category),4);return b;}
std::string name_at(const Bytes& response,std::size_t index){const auto begin=response.begin()+static_cast<std::ptrdiff_t>(12+44*index);const auto end=std::find(begin,begin+32,0);return {begin,end};}
std::uint32_t value(const Bytes& response,std::size_t index,std::size_t column){return read_le(View(response).subspan(12+44*index+32+4*column,4));}
}
int main(){try{
    const auto path=std::filesystem::absolute("ranking-test-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    Storage accounts(path);RichonlineRankingStore store(path);
    const auto empty=store.response(query(1));check(empty&&empty->size()==12&&read_le(View(*empty).subspan(8,4))==0,"empty database must be empty rank");
    const auto add=[&](const char* name,int wins,int level,double gold){auto role=accounts.dispatch("accounts.create",{{"username",name},{"password","test"}}).at("account");accounts.dispatch("accounts.update",{{"role_id",role.at("role_id")},{"expected",{{"wins",role.at("wins")},{"level",role.at("level")},{"gold",role.at("gold")}}},{"changes",{{"wins",wins},{"level",level},{"gold",gold}}},{"reason","ranking evidence fixture"}});return role.at("role_id").get<std::int64_t>();};
    const auto a=add("A",10,5,200.5);add("B",7,12,200.75);add("C",7,10,500);
    const auto wins=*store.response(query(1));check(name_at(wins,0)=="A"&&name_at(wins,1)=="B"&&name_at(wins,2)=="C","wins rank and stable tie");
    check(value(wins,0,0)==10&&value(wins,0,1)==5&&value(wins,0,2)==200,"typed rank fields");
    const auto levels=*store.response(query(2));check(name_at(levels,0)=="B"&&name_at(levels,1)=="C","level rank");
    const auto gold=*store.response(query(3));check(name_at(gold,0)=="C"&&name_at(gold,1)=="B"&&name_at(gold,2)=="A","full precision gold ordering");
    check(value(gold,1,2)==200&&value(gold,2,2)==200,"whole gold display");
    for(std::size_t n=0;n<10;++n)check(!store.response(View(query(1)).first(n)),"partial ranking query");
    rejects([&]{store.response(query(4));},"ranking_category_unknown");
    accounts.dispatch("accounts.update",{{"role_id",a},{"expected",{{"wins",10}}},{"changes",{{"wins",11}}},{"reason","committed settlement fixture"}});
    check(value(*store.response(query(1)),0,0)==11,"rank observes committed role updates");
    accounts.dispatch("accounts.update",{{"role_id",a},{"expected",{{"gold",200.5}}},{"changes",{{"gold",2147483648.0}}},{"reason","overflow boundary"}});
    rejects([&]{store.response(query(3));},"ranking_gold_out_of_wire_range");
    std::cout<<"PASS inquiry type1 real SQLite roles, all category orderings, field offsets, precision and bounds\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
