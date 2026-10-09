#include "richonline_game_payment.hpp"
#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <chrono>
#include <future>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class F>void invalid(F action){try{action();}catch(const CodecError&){return;}throw std::runtime_error("missing CodecError");}
RichonlineGoldCharges text_charges(const std::string& text){return parse_richonline_gold_charges(View(reinterpret_cast<const std::uint8_t*>(text.data()),text.size()));}
std::shared_ptr<RichonlineGameLedger> ledger(std::uint32_t reserve){return std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1000,2000,50,reserve}});}
struct Fixture {
    std::filesystem::path path;Storage storage;std::int64_t role;
    Fixture(std::filesystem::path file,int gold):path(std::move(file)),storage(path),
        role(storage.dispatch("accounts.create",{{"username","payment-owner"},{"password","isolated"}}).at("account").at("role_id").get<std::int64_t>()) {
        sql("UPDATE roles SET gold="+std::to_string(gold));
    }
    void sql(const std::string& query){sqlite3* db=nullptr;const auto name=path.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"sqlite open");
        const auto rc=sqlite3_exec(db,query.c_str(),nullptr,nullptr,nullptr);sqlite3_close(db);check(rc==SQLITE_OK,"sqlite fixture");}
    auto debit(){return [this](const GameGoldCharge& charge){return storage.consume_game_gold("payment-owner",role,charge);};}
    double gold(){return storage.roles_for_username("payment-owner").at(0).at("gold").get<double>();}
};
void resources(const RichonlineGoldCharges& charges){
    check(charges.require(0)==160 && charges.require(3)==300 && charges.require(4)==250 && charges.require(5)==300 && charges.require(6)==2000,"actual GoldCharge values");
    for(const auto* text:{"", "[ITEM]\nindx=3\nvalue=300", "[ITEM]\nindx=3\ncharge=-1", "[ITEM]\nindx=3\ncharge=300\n[ITEM]\nindx=3\ncharge=300", "[ITEM]\nindx=3\ncharge=2147483648"})invalid([&]{text_charges(text);});
    check(richonline_initial_reserve(0,200,charges)==300,"reserve floor grants no DB credit");
    check(richonline_initial_reserve(1000.9,200,charges)==800,"reserve truncation");
    invalid([&]{richonline_initial_reserve(1e30,0,charges);});
    invalid([&]{richonline_initial_reserve(100,0,{});});
}
void persistent(const std::filesystem::path& root,const RichonlineGoldCharges& charges){
    Fixture empty(root/"empty.sqlite3",0);auto empty_ledger=ledger(richonline_initial_reserve(0,0,charges));
    RichonlineGamePayment refused(empty_ledger,0,charges,empty.debit());
    check(refused.paid_die("poor",6,{false,false}).status==RichonlinePaymentStatus::account_refused,"floor cannot fund payment");
    check(empty.gold()==0 && refused.reserve()==300,"floor/account refusal conservation");
    Fixture f(root/"paid.sqlite3",500);auto funds=ledger(richonline_initial_reserve(500,200,charges));
    RichonlineGamePayment payment(funds,0,charges,f.debit());check(f.gold()==500,"constructor must not debit entry fee");
    const auto paid=payment.paid_die("chosen-six",6,{false,false});
    check(paid.status==RichonlinePaymentStatus::committed && paid.charge==300 && paid.reserve_after==0 && f.gold()==200,"paid die conservation");
    check(payment.paid_die("chosen-six",6,{false,false}).status==RichonlinePaymentStatus::duplicate && f.gold()==200 && payment.reserve()==0,"duplicate charged twice");
    invalid([&]{payment.paid_die("chosen-six",1,{false,false});});
    check(payment.shop_refresh("refresh").status==RichonlinePaymentStatus::insufficient_reserve && f.gold()==200,"shared reserve shop refusal");
    auto restored=ledger(300);RichonlineGamePayment replay(restored,0,charges,f.debit());
    check(replay.paid_die("chosen-six",6,{false,false}).status==RichonlinePaymentStatus::recovery_required && replay.reserve()==300 && f.gold()==200,"DB replay requires gameplay recovery");
    check(replay.paid_die("chosen-six",6,{false,false}).status==RichonlinePaymentStatus::recovery_required,"recovery became success");
}
void equipment(const std::filesystem::path& root,const RichonlineGoldCharges& charges){
    Fixture f(root/"equipment.sqlite3",1000);auto funds=ledger(1000);RichonlineGamePayment payment(funds,0,charges,f.debit());
    check(payment.paid_die("free",2,{true,true}).charge==0 && f.gold()==1000 && payment.reserve()==1000,"free precedence");
    check(payment.paid_die("discount",2,{false,true}).charge==150 && f.gold()==850 && payment.reserve()==850,"vehicle half price");
    check(payment.shop_refresh("refresh").charge==250 && f.gold()==600 && payment.reserve()==600,"shared shop payment");
    const auto state=funds->snapshot(0).funds;check(state.cash==1000 && state.deposit==2000 && state.tickets==50,"wrong gameplay ledger debited");
}
void random_dice_resources_and_sqlite(const std::filesystem::path& root,const RichonlineGoldCharges& charges){
    check(charges.require(0)==160 && charges.require(1)==240 && charges.require(2)==160,"actual random dice resources");
    Fixture f(root/"random-dice.sqlite3",2000);auto funds=ledger(2000);RichonlineGamePayment payment(funds,0,charges,f.debit());
    using Vehicle=RichonlineDiceVehicle;
    for(const auto& [vehicle,expected]:std::array<std::pair<Vehicle,std::array<std::int32_t,3>>,3>{{
        {Vehicle::walking,{0,160,240}},{Vehicle::motorcycle,{0,0,160}},{Vehicle::car,{0,0,0}}}}){
        for(std::uint8_t count=1;count<=3;++count){
            const RichonlinePaidDiceEquipment equipped{true,true,vehicle};
            check(payment.quote_random_dice(count,equipped)==expected[count-1],"controlled_die_discount_leaked_to_random_dice");
        }
    }
    const auto paid=payment.random_dice("walking-three",3,{true,true,Vehicle::walking});
    check(paid.status==RichonlinePaymentStatus::committed && paid.charge==240 && payment.reserve()==1760 && f.gold()==1760,
        "random_dice_sqlite_reserve_charge_wrong");
    check(payment.random_dice("walking-three",3,{true,true,Vehicle::walking}).status==RichonlinePaymentStatus::duplicate &&
        f.gold()==1760,"random_dice_duplicate_charged_again");
    invalid([&]{payment.random_dice("walking-three",2,{true,true,Vehicle::walking});});
    check(payment.random_dice("motorcycle-three",3,{false,false,Vehicle::motorcycle}).charge==160 &&
        payment.random_dice("motorcycle-two",2,{false,false,Vehicle::motorcycle}).charge==0 &&
        payment.random_dice("car-three",3,{false,false,Vehicle::car}).charge==0 && f.gold()==1600 && payment.reserve()==1600,
        "vehicle_random_dice_fee_wrong");
    for(const auto count:std::array<std::uint8_t,3>{0,4,255})invalid([&]{payment.quote_random_dice(count,{});});
    invalid([&]{payment.quote_random_dice(2,{false,false,static_cast<Vehicle>(99)});});
}
void races(const std::filesystem::path& root,const RichonlineGoldCharges& charges){
    Fixture f(root/"concurrent.sqlite3",1000);auto funds=ledger(1000);RichonlineGamePayment payment(funds,0,charges,f.debit());
    std::vector<std::future<RichonlinePaymentResult>> replies;
    for(int i=0;i<8;++i)replies.push_back(std::async(std::launch::async,[&]{return payment.paid_die("same",3,{false,false});}));
    int fresh=0,duplicate=0;for(auto& future:replies){auto result=future.get();fresh+=result.status==RichonlinePaymentStatus::committed;duplicate+=result.status==RichonlinePaymentStatus::duplicate;}
    check(fresh==1 && duplicate==7 && f.gold()==700 && payment.reserve()==700,"concurrent duplicate conservation");
    std::promise<void> entered,release;auto released=release.get_future().share();
    RichonlineGamePayment raced(funds,0,charges,[&](const GameGoldCharge& charge){auto result=f.debit()(charge);entered.set_value();released.wait();return result;});
    auto paying=std::async(std::launch::async,[&]{return raced.paid_die("raced",1,{false,false});});
    entered.get_future().wait();
    auto unrelated=std::async(std::launch::async,[&]{const auto old=funds->snapshot(0);return funds->adjust(0,old,{1,0,0,0});});
    const auto blocked=unrelated.wait_for(std::chrono::milliseconds(20))==std::future_status::timeout;
    release.set_value();const auto paid=paying.get();const auto changed=unrelated.get();
    check(blocked && paid.status==RichonlinePaymentStatus::committed && f.gold()==400 && raced.reserve()==400 && changed.funds.cash==1001,"DB and reserve lock ordering");
    check(raced.paid_die("raced",1,{false,false}).status==RichonlinePaymentStatus::duplicate && f.gold()==400,"concurrent commit double debit");
    f.sql("CREATE TRIGGER fail_charge BEFORE INSERT ON audit WHEN NEW.source='native-game-charge' BEGIN SELECT RAISE(ABORT,'injected'); END");
    bool failed=false;try{payment.paid_die("db-failure",4,{false,false});}catch(const StorageError&){failed=true;}
    check(failed && f.gold()==400 && payment.reserve()==400,"DB failure mutated reserve");
}
}
int main(int argc,char** argv){try{
    check(argc==2,"pass actual NEW GoldCharge.kpd path");const auto charges=load_richonline_gold_charges(std::filesystem::path(argv[1]));
    const auto root=std::filesystem::temp_directory_path()/("game-payment-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);resources(charges);persistent(root,charges);equipment(root,charges);races(root,charges);
    random_dice_resources_and_sqlite(root,charges);
    std::cout<<"PASS actual NEW GoldCharge, reserve floor, SQLite paid/free/discount/shop, idempotency, races, recovery and rollback\n";
}catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}}
