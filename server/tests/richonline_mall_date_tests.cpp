#include "storage_detail.hpp"
#include "richonline_mall_service.hpp"
#include <windows.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class Action>void rejects(Action action,const char* reason){try{action();}catch(const std::runtime_error& error){if(std::string_view(error.what())!=reason)throw std::runtime_error(std::string("wrong rejection: ")+error.what());return;}throw std::runtime_error("expected rejection");}
Frame selection(){Bytes payload;append_le(payload,static_cast<std::uint32_t>(-1),4);return {16,std::move(payload)};}
Frame buy(std::uint32_t key){Bytes payload;for(auto word:std::array<std::uint32_t,4>{0,1,key,1})append_le(payload,word,4);return {18,std::move(payload)};}
Frame activate(std::uint32_t key){Bytes payload;append_le(payload,2,4);append_le(payload,key,4);return {63,std::move(payload)};}
struct Db {
    sqlite3* db{};explicit Db(const std::filesystem::path& path){const auto u=path.u8string();check(sqlite3_open_v2(reinterpret_cast<const char*>(u.c_str()),&db,SQLITE_OPEN_READWRITE,nullptr)==SQLITE_OK,"open fixture db");}~Db(){sqlite3_close(db);}
};
}
int main(int argc,char** argv){try{
    if(argc!=2)throw std::runtime_error("NEW client resource root required");
    const auto catalog=RichonlineMallCatalog::load(std::filesystem::path(argv[1]));
    const auto path=std::filesystem::absolute("mall-date-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    const auto modern=RichonlineInventoryDateVersion::compat_2021_v1;
    constexpr std::int64_t now=1791504000; //2026-10-09T00:00:00Z
    const std::string evidence="NEW date2021 compatible client verified; original resource calendar term and zero jhDay retains existing expiry";
    Storage storage(path);const auto initial=storage.dispatch("accounts.create",{{"username","Date"},{"password","test"}}).at("account");
    const auto id=initial.at("role_id").get<std::int64_t>();
    storage.dispatch("accounts.update",{{"role_id",id},{"expected",{{"coins",initial.at("coins")},{"gold",initial.at("gold")}}},{"changes",{{"coins",1000.0},{"gold",100000.0}}},{"reason","date fixture wallets"}});
    storage.ensure_test_rp_certificate("Date",now); //named no-date key13 survives
    storage.require_inventory_date_version(RichonlineInventoryDateVersion::original_2005);
    rejects([&]{storage.require_inventory_date_version(modern);},"inventory_date_database_mode_mismatch");
    rejects([&]{RichonlineMallService service(catalog,"bad",{0,0,-13,evidence,modern,{}});},"mall_client_date_mode_mismatch");
    RichonlineMallService original(catalog,"original",{0,0,-13,evidence});original.request(storage,"Date",id,selection(),now);
    const auto refused=*original.request(storage,"Date",id,buy(0x1004),now);
    check(refused.diagnostic=="inventory_date_year_unrepresentable"&&refused.frames[0].wire_type==0xffffffffU,"old client2026 purchase not rejected");
    check(storage.roles_for_username("Date")[0].at("coins")==1000.0,"original date refusal charged");
    Db db(path);storage_detail::execute(db.db,"INSERT INTO metadata(key,value) VALUES('inventory_date_version','richonline-inventory-date-2021-v1');");
    rejects([&]{storage.require_inventory_date_version(RichonlineInventoryDateVersion::original_2005);},"inventory_date_database_mode_mismatch");
    RichonlineMallService service(catalog,"modern",{0,0,-13,evidence,modern,std::string(richonline_inventory_compatibility_id)});
    service.request(storage,"Date",id,selection(),now);const auto purchase=*service.request(storage,"Date",id,buy(0x1004),now);
    check(purchase.diagnostic=="purchased_timed"&&purchase.role_refresh&&!purchase.role_refresh_after_frames&&purchase.frames[0].wire_type==77,"timed purchase ordering");
    const auto purchased_key=read_le(View(purchase.frames[0].payload).subspan(4,4));
    const auto expected_expiry=richonline_inventory_calendar_expiry(now,1,0,0);
    check(decode_richonline_inventory_date(purchased_key,modern)==RichonlineInventoryDate{2027,10,9},"real product4 year term encoded wrong");
    check(purchase.role_refresh->at("coins")==999.0&&purchase.role_refresh->at("purchase_score")==10,"real product price/score lost");
    auto inventory=storage.lobby_inventory("Date",id,now);
    check(std::find(inventory.items.begin(),inventory.items.end(),purchased_key)!=inventory.items.end()&&inventory.equipment[13]==13,"new date inventory/certificate");
    inventory=storage.lobby_inventory("Date",id,expected_expiry);
    check(std::find(inventory.items.begin(),inventory.items.end(),purchased_key)==inventory.items.end(),"authoritative expiry did not expire");
    // Select an actual resource with a gold activation price, not a synthetic fee.
    std::uint32_t inactive=0;double fee=0;
    const auto entitlement_expiry=richonline_inventory_calendar_expiry(now,0,0,2);
    for(const auto& [item,product]:catalog.products()) {
        if(product.source_fields.contains("beanJ")&&product.source_fields.at("beanJ")!="0") {
            inactive=richonline_inventory_key_from_expiry(0x40001000U|item,entitlement_expiry,modern);
            fee=catalog.activation_charge(inactive,RichonlineMallCurrency::gold);break;
        }
    }
    check(inactive!=0&&fee>0,"actual activation product missing");
    storage_detail::Statement seed(db.db,"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES('Date',?,?)");seed.bind(1,inactive);seed.bind(2,entitlement_expiry);seed.row();
    const auto activated=*service.request(storage,"Date",id,activate(inactive),now);
    check(activated.diagnostic=="activated"&&activated.role_refresh_after_frames&&activated.frames[0].wire_type==213&&activated.frames[0].payload.size()==20,"activation213/current profile order");
    const auto new_key=read_le(View(activated.frames[0].payload).subspan(4,4));
    check(new_key==(inactive&~0x40000000U)&&activated.role_refresh->at("gold")==100000.0-fee,"actual zero jhDay activation lost expiry or wallet");
    const auto replay=storage.activate_mall_item("Date",id,catalog,{RichonlineMallCurrency::gold,inactive},now,modern,"modern:2",evidence);
    check(replay.status==RichonlineMallActivationStatus::replayed&&replay.role.at("gold")==100000.0-fee,"activation replay double debit");
    rejects([&]{storage.activate_mall_item("Date",id,catalog,{RichonlineMallCurrency::gold,inactive},now,RichonlineInventoryDateVersion::original_2005,"wrong-mode",evidence);},"inventory_date_database_mode_mismatch");
    const auto missing=*service.request(storage,"Date",id,activate(inactive),now);check(missing.diagnostic=="mall_activation_item_missing"&&missing.frames[0].wire_type==0xffffffffU,"activation business missing closed connection");
    std::cout<<"PASS actual NEW2026 timed purchase/date2027/77/profile order, original/mixed mode refusal, expiry, real activation tariff/213/replay and no-date PK certificate\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
