#include "richonline_account_services.hpp"

#include <sqlite3.h>
#include <windows.h>
#include <bit>
#include <chrono>
#include <iostream>
#include <limits>

namespace {
using namespace richnet;
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
Bytes amount(double value) {
    Bytes bytes;
    const auto bits=std::bit_cast<std::uint64_t>(value);
    for (std::size_t i=0;i<8;++i) bytes.push_back(static_cast<std::uint8_t>(bits>>(8*i)));
    return bytes;
}
void sql(const std::filesystem::path& path, const char* text) {
    sqlite3* db=nullptr;
    const auto name=path.u8string();
    check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"fixture open");
    const auto result=sqlite3_exec(db,text,nullptr,nullptr,nullptr);
    sqlite3_close(db);
    check(result==SQLITE_OK,"fixture SQL");
}
void error(const RichonlineAccountReply& reply,std::uint32_t wire,std::int32_t reason) {
    check(reply.response.wire_type==0xffffffffU,"business error wire");
    check(reply.response.payload.size()==9 && reply.response.payload[8]==0,"empty context is one NUL");
    check(read_le(View(reply.response.payload).first(4))==wire,"error request context");
    check(read_le(View(reply.response.payload).subspan(4,4))==static_cast<std::uint32_t>(reason),"error reason");
    check(!reply.updated_role && !reply.rejection.empty(),"failed operation result");
}
template<class Action> void malformed(Action action) {
    try {action();} catch(const CodecError&) {return;}
    throw std::runtime_error("malformed structure accepted");
}
}

int main() {
    try {
        const auto base=std::filesystem::temp_directory_path()/
            ("richonline-account-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(base);
        const auto path=base/"account.sqlite3";
        Storage storage(path,ClientProfile::richonline);
        const auto id=storage.dispatch("accounts.create",{{"username","AccountFixture"},{"password","isolated-test"}})
            .at("account").at("role_id").get<std::uint32_t>();
        sql(path,"UPDATE roles SET coins=100,gold=200,bank=100");
        const RichonlineAccountPolicy policy{{10,5,1000},100};
        const auto request=[&](std::uint32_t wire,Bytes data) {
            auto reply=richonline_account_request(storage,"AccountFixture",id,{wire,std::move(data)},policy);
            check(reply.has_value(),"known financial wire handled"); return std::move(*reply);
        };
        auto reply=request(61,amount(25));
        check(reply.response.wire_type==101 && reply.response.payload==amount(25),"deposit delta reply");
        reply=request(62,amount(5));
        check(reply.response.wire_type==102 && reply.response.payload==amount(5),"withdraw delta reply");
        auto role=storage.roles_for_username("AccountFixture").at(0);
        check(role["gold"]==180 && role["bank"]==120 && role["coins"]==100,"bank atomic balances");
        const auto before=role;
        for (double value : {0.0,-1.0,4.0,std::numeric_limits<double>::infinity(),std::numeric_limits<double>::quiet_NaN()})
            error(request(61,amount(value)),61,-131);
        error(request(61,amount(181)),61,-124);
        error(request(62,amount(121)),62,-124);
        malformed([&]{request(61,Bytes(7));});
        check(storage.roles_for_username("AccountFixture").at(0)==before,"rejections preserve account");
        Bytes exchange;
        append_le(exchange,1,4);append_le(exchange,2,4);
        const auto two=amount(2);exchange.insert(exchange.end(),two.begin(),two.end());
        reply=request(42,exchange);
        check(reply.response.wire_type==79 && reply.response.payload.size()==24,"NEW exchange reply shape");
        check(read_le(View(reply.response.payload).first(4))==1 && read_le(View(reply.response.payload).subspan(4,4))==2,"currency identity echo");
        check(Bytes(reply.response.payload.begin()+16,reply.response.payload.end())==amount(200),"exchange gold delta");
        role=storage.roles_for_username("AccountFixture").at(0);
        check(role["coins"]==98 && role["gold"]==380 && role["bank"]==120,"exchange persists both balances");
        check(reply.updated_role && *reply.updated_role==role,"committed role snapshot");
        exchange.resize(24,0);malformed([&]{request(42,exchange);});
        exchange.resize(16);exchange[0]=2;malformed([&]{request(42,exchange);});
        exchange[0]=1;
        const auto too_much=amount(101);
        std::copy(too_much.begin(),too_much.end(),exchange.begin()+8);
        error(request(42,exchange),42,-112);
        const auto fractional=amount(1.5);
        std::copy(fractional.begin(),fractional.end(),exchange.begin()+8);
        error(request(42,exchange),42,-112);
        check(storage.roles_for_username("AccountFixture").at(0)==role,"invalid exchange has no writes");
        sql(path,"CREATE TRIGGER reject_account_audit BEFORE INSERT ON audit WHEN NEW.source='native-bank' BEGIN SELECT RAISE(ABORT,'fixture'); END;");
        reply=request(61,amount(10));error(reply,61,-112);
        check(storage.roles_for_username("AccountFixture").at(0)==role,"audit failure rolls back balances");
        sql(path,"DROP TRIGGER reject_account_audit");
        reply=request(61,amount(10));check(reply.response.wire_type==101,"operation usable after rollback");
        const auto wrong=richonline_account_request(storage,"DifferentOwner",id,{62,amount(5)},policy);
        check(wrong.has_value(),"ownership failure handled");error(*wrong,62,-112);
        check(!richonline_account_request(storage,"AccountFixture",id,{27,{}},policy),"unowned wire not swallowed");
        Bytes config,completion(4);
        for(double value:{0.0,10.0,5.0,1000.0}) {const auto data=amount(value);config.insert(config.end(),data.begin(),data.end());}
        for(double value:{0.0,0.0,100.0}) {const auto data=amount(value);completion.insert(completion.end(),data.begin(),data.end());}
        const auto parsed=richonline_account_policy(config,completion);
        check(parsed.bank.minimum_deposit==10 && parsed.bank.minimum_withdrawal==5 && parsed.bank.capacity==1000 && parsed.exchange_ratio==100,"bootstrap policy offsets");
        const auto fraction=amount(2.5);
        std::copy(fraction.begin(),fraction.end(),completion.begin()+20);
        check(richonline_account_policy(config,completion).exchange_ratio==2.5,"fractional ratio preserved");
        for(double value:{0.0,-1.0,std::numeric_limits<double>::infinity(),std::numeric_limits<double>::quiet_NaN()}) {
            const auto invalid=amount(value);std::copy(invalid.begin(),invalid.end(),completion.begin()+20);
            malformed([&]{static_cast<void>(richonline_account_policy(config,completion));});
        }
        const auto pre_fraction=storage.roles_for_username("AccountFixture").at(0);
        const auto converted=storage.exchange_gold("AccountFixture",id,{3,2.5});
        check(converted.status==ExchangeStatus::success && converted.role.has_value(),"fractional ratio transaction");
        check(converted.role->at("gold").get<double>()==pre_fraction.at("gold").get<double>()+7.5 &&
            converted.role->at("coins").get<double>()==pre_fraction.at("coins").get<double>()-3,"fractional amounts exact");
        const auto snapshot=storage.roles_for_username("AccountFixture");
        Storage reopened(path,ClientProfile::richonline);
        check(reopened.roles_for_username("AccountFixture")==snapshot,"SQLite restart persistence");
        std::cout<<"PASS NEW account bank/exchange boundaries, SQLite atomic rollback and persistence\n";
    } catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
