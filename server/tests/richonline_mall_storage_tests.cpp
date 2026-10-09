#include "storage_detail.hpp"
#include <windows.h>
#include <chrono>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class Action> void rejects(Action action,const char* reason){try{action();}catch(const std::runtime_error& error){if(std::string_view(error.what())!=reason)throw std::runtime_error(std::string("wrong rejection: ")+error.what());return;}throw std::runtime_error("expected rejection");}
Bytes bytes(std::string_view text){return {text.begin(),text.end()};}
RichonlineMallCatalog catalog(){return RichonlineMallCatalog::parse(bytes(
    "[PROP]\nindx=13\nname=Fixture\ntype=FUNC\nchType=FUNC_DT\nenable=true\nsaleLJ=true\nsaleLR=true\npriceLJ=1.5\npriceLR=200\nscore=15\ndayJ=30\ndayR=7\nbeanP=11\nbeanJ=12\nbeanR=13\njhdbP=21\njhdbJ=22\njhdbR=23\n"),bytes("[A_ZJ_J]\nprop=13\n[A_ZJ_R]\nprop=13\n"));}
struct Database {
    sqlite3* db{};
    explicit Database(const std::filesystem::path& path){const auto u8=path.u8string();check(sqlite3_open_v2(reinterpret_cast<const char*>(u8.c_str()),&db,SQLITE_OPEN_READWRITE,nullptr)==SQLITE_OK,"test db open");}
    ~Database(){sqlite3_close(db);}
    std::int64_t count(const char* sql){storage_detail::Statement query(db,sql);check(query.row(),"count absent");return query.integer(0);}
};
}
int main(){try{
    const auto path=std::filesystem::absolute("mall-test-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))/"accounts.sqlite3";
    const auto products=catalog();
    for(std::uint32_t source=0;source<3;++source) {
        const auto key=0x4000000dU|(source<<12U);
        check(products.activation_charge(key,RichonlineMallCurrency::gold)==11.0+source,"activation gold tariff source mismatch");
        check(products.activation_charge(key,RichonlineMallCurrency::m_points)==21.0+source,"activation M-point tariff source mismatch");
    }
    rejects([&]{products.activation_charge(13,RichonlineMallCurrency::gold);},"mall_activation_item_state_invalid");
    rejects([&]{products.activation_charge(0x4001000dU,RichonlineMallCurrency::gold);},"mall_activation_item_state_invalid");
    rejects([&]{products.activation_charge(0x4000300dU,RichonlineMallCurrency::gold);},"mall_activation_source_currency_invalid");
    Bytes activation;append_le(activation,2,4);append_le(activation,0x4000100dU,4);
    const auto activate=decode_richonline_mall_activate63(activation);
    check(activate.currency==RichonlineMallCurrency::gold&&activate.owned_key==0x4000100dU,"activation request order");
    activation.push_back(0);rejects([&]{decode_richonline_mall_activate63(activation);},"mall_activate63_size_invalid");
    const auto activated=encode_richonline_mall_activated213({0x4000100dU,0x3442100dU,RichonlineMallCurrency::gold,12.0});
    check(activated.wire_type==213&&activated.payload.size()==20&&read_le(View(activated.payload).subspan(8,4))==2,"activation response shape");
    check(activated.payload[18]==40&&activated.payload[19]==64,"activation price must be f64 12");
    rejects([&]{encode_richonline_mall_activated213({0x4000100dU,0x3442100eU,RichonlineMallCurrency::gold,12.0});},"mall_activation_result_invalid");
    std::int64_t id=0;
    // A historical representable key is explicit fixture data; it is not a 2026 date workaround.
    RichonlineMallPurchase purchase{"mall-1",{0x100d},{0x3442000d,1514764800,7,9,"synthetic fixture adapter; opaque words explicitly 7/9"}};
    {
        Storage accounts(path);const auto initial=accounts.dispatch("accounts.create",{{"username","Player"},{"password","test"}}).at("account");id=initial.at("role_id").get<std::int64_t>();
        accounts.dispatch("accounts.create",{{"username","Other"},{"password","test"}});
        accounts.dispatch("accounts.update",{{"role_id",id},{"expected",{{"coins",initial.at("coins")},{"gold",initial.at("gold")}}},{"changes",{{"coins",100.0},{"gold",1000.0}}},{"reason","mall fixture wallets"}});
        Bytes packet;for(const auto word:std::array<std::uint32_t,4>{0,1,0x100d,1})append_le(packet,word,4);
        check(decode_richonline_mall_purchase18(packet).encoded_item==0x100d,"wire18 key");
        packet.push_back(0);rejects([&]{decode_richonline_mall_purchase18(packet);},"mall_purchase18_size_invalid");packet.pop_back();packet[12]=2;
        rejects([&]{decode_richonline_mall_purchase18(packet);},"mall_purchase18_shape_invalid");
        const auto notice=encode_richonline_mall_added77(purchase.grant);
        check(notice.wire_type==77&&notice.payload.size()==12&&read_le(View(notice.payload).first(4))==7&&read_le(View(notice.payload).subspan(4,4))==purchase.grant.owned_key&&read_le(View(notice.payload).subspan(8,4))==9,"wire77 lost explicit opaque fields");
        rejects([&]{accounts.purchase_mall_item("Other",id,products,purchase,100);},"mall_role_not_owned");
        auto bad=purchase;bad.grant.evidence.clear();rejects([&]{accounts.purchase_mall_item("Player",id,products,bad,100);},"mall_grant_evidence_required");
        bad=purchase;bad.grant.expires_at=0;rejects([&]{accounts.purchase_mall_item("Player",id,products,bad,100);},"mall_purchase_timed_product_requires_expiry");
        const auto first=accounts.purchase_mall_item("Player",id,products,purchase,100);
        check(first.status==RichonlineMallPurchaseStatus::purchased&&first.role.at("coins")==98.5&&first.role.at("gold")==1000.0&&first.role.at("purchase_score")==15,"purchase wallet/score");
        check(accounts.lobby_inventory("Player",id,100).items==std::vector<std::uint32_t>{purchase.grant.owned_key},"inventory not shared");
        Database database(path);check(database.count("SELECT count(*) FROM audit WHERE source='native-mall'")==3,"purchase audit incomplete");
        auto repeat=purchase;repeat.operation_id="same-key";
        check(accounts.purchase_mall_item("Player",id,products,repeat,100).status==RichonlineMallPurchaseStatus::inventory_conflict,"duplicate full key overwritten");
        bad=purchase;bad.grant.opaque_word0=8;rejects([&]{accounts.purchase_mall_item("Player",id,products,bad,100);},"mall_purchase_operation_conflict");
        auto gold=purchase;gold.operation_id="gold";gold.request.encoded_item=0x200d;gold.grant.owned_key=0x3444000d;gold.grant.expires_at=1514851200;
        const auto second=accounts.purchase_mall_item("Player",id,products,gold,100);
        check(second.status==RichonlineMallPurchaseStatus::purchased&&second.role.at("coins")==98.5&&second.role.at("gold")==800.0&&second.role.at("purchase_score")==30,"gold purchase changed wrong wallet");
        const auto replay=accounts.purchase_mall_item("Player",id,products,purchase,100);
        check(replay.status==RichonlineMallPurchaseStatus::replayed&&replay.role.at("gold")==800.0&&replay.role.at("purchase_score")==30,"replay returned historical role or charged twice");
        auto rollback=purchase;rollback.operation_id="rollback";rollback.grant.owned_key=0x3446000d;rollback.grant.expires_at=1514937600;
        storage_detail::execute(database.db,"CREATE TRIGGER fail_mall_audit BEFORE INSERT ON audit WHEN NEW.source='native-mall' BEGIN SELECT RAISE(ABORT,'test'); END;");
        rejects([&]{accounts.purchase_mall_item("Player",id,products,rollback,100);},"database_constraint_failed");
        check(database.count("SELECT count(*) FROM native_mall_purchases")==2&&database.count("SELECT count(*) FROM lobby_inventory")==2,"failed audit persisted partial purchase");
        check(accounts.roles_for_username("Player")[0].at("coins")==98.5,"rollback lost funds");
        storage_detail::execute(database.db,"DROP TRIGGER fail_mall_audit;");
        accounts.dispatch("accounts.update",{{"role_id",id},{"expected",{{"gold",800.0}}},{"changes",{{"gold",0.0}}},{"reason","funds test"}});
        gold.operation_id="no-funds";gold.grant.owned_key=0x3448000d;gold.grant.expires_at=1515024000;
        check(accounts.purchase_mall_item("Player",id,products,gold,100).status==RichonlineMallPurchaseStatus::insufficient_funds,"insufficient purchase accepted");
        check(database.count("SELECT count(*) FROM native_mall_purchases")==2,"failed purchase receipt created");
        const auto capacity_role=accounts.dispatch("accounts.create",{{"username","Capacity"},{"password","test"}}).at("account");
        const auto capacity_id=capacity_role.at("role_id").get<std::int64_t>();
        accounts.dispatch("accounts.update",{{"role_id",capacity_id},{"expected",{{"coins",capacity_role.at("coins")}}},{"changes",{{"coins",100.0}}},{"reason","capacity fixture"}});
        for(std::uint32_t i=1;i<=8;++i) {
            storage_detail::Statement seed(database.db,"INSERT INTO lobby_inventory(username,encoded_item,expires_at) VALUES('Capacity',?,?)");
            seed.bind(1,0x3000000dU+(i<<17U));seed.bind(2,i==8?50:0);seed.row();
        }
        auto capacity_purchase=purchase;capacity_purchase.operation_id="capacity-eight";
        check(accounts.purchase_mall_item("Capacity",capacity_id,products,capacity_purchase,100).status==RichonlineMallPurchaseStatus::purchased,"expired item counted toward active client slots");
        capacity_purchase.operation_id="capacity-nine";capacity_purchase.grant.owned_key=0x3446000d;capacity_purchase.grant.expires_at=1514937600;
        const auto full=accounts.purchase_mall_item("Capacity",capacity_id,products,capacity_purchase,100);
        check(full.status==RichonlineMallPurchaseStatus::inventory_full&&full.role.at("coins")==98.5,"full inventory charged or overfilled");
    }
    {Storage reopened(path);const auto result=reopened.purchase_mall_item("Player",id,products,purchase,2100000000);check(result.status==RichonlineMallPurchaseStatus::replayed&&result.role.at("gold")==0.0,"persistent replay failed after grant expiry");}
    {
        Storage accounts(path);const auto initial=accounts.dispatch("accounts.create",{{"username","Activation"},{"password","test"}}).at("account");const auto role=initial.at("role_id").get<std::int64_t>();
        accounts.dispatch("accounts.update",{{"role_id",role},{"expected",{{"coins",initial.at("coins")},{"gold",initial.at("gold")}}},{"changes",{{"coins",100.0},{"gold",100.0}}},{"reason","activation fixture"}});
        constexpr std::int64_t activation_now=1514764800,expiry=1514851200;
        const auto inactive=richonline_inventory_key_from_expiry(0x4000100dU,expiry,RichonlineInventoryDateVersion::original_2005);
        const auto active=inactive&~0x40000000U;Database database(path);
        {storage_detail::Statement seed(database.db,"INSERT INTO lobby_inventory VALUES('Activation',?,?)");seed.bind(1,inactive);seed.bind(2,expiry);seed.row();}
        {storage_detail::Statement seed(database.db,"INSERT INTO lobby_equipment VALUES(?,5,?)");seed.bind(1,role);seed.bind(2,inactive);seed.row();}
        storage_detail::execute(database.db,"CREATE TRIGGER fail_activation_audit BEFORE INSERT ON audit WHEN NEW.source='native-mall' BEGIN SELECT RAISE(ABORT,'test'); END;");
        rejects([&]{accounts.activate_mall_item("Activation",role,products,{RichonlineMallCurrency::gold,inactive},activation_now,RichonlineInventoryDateVersion::original_2005,"activate-rollback","fixture");},"database_constraint_failed");
        check(accounts.roles_for_username("Activation")[0].at("gold")==100.0&&accounts.lobby_inventory("Activation",role,activation_now).equipment[5]==inactive,"activation audit rollback changed wallet/equipment");
        check(database.count("SELECT count(*) FROM native_mall_activations")==0,"failed activation receipt persisted");
        storage_detail::execute(database.db,"DROP TRIGGER fail_activation_audit;");
        {storage_detail::Statement conflict(database.db,"INSERT INTO lobby_inventory VALUES('Activation',?,?)");conflict.bind(1,active);conflict.bind(2,expiry);conflict.row();}
        check(accounts.activate_mall_item("Activation",role,products,{RichonlineMallCurrency::gold,inactive},activation_now,RichonlineInventoryDateVersion::original_2005,"activate-conflict","fixture").status==RichonlineMallActivationStatus::inventory_conflict,"activation replaced conflicting key");
        {storage_detail::Statement remove(database.db,"DELETE FROM lobby_inventory WHERE username='Activation' AND encoded_item=?");remove.bind(1,active);remove.row();}
        accounts.dispatch("accounts.update",{{"role_id",role},{"expected",{{"gold",100.0}}},{"changes",{{"gold",0.0}}},{"reason","activation insufficient fixture"}});
        check(accounts.activate_mall_item("Activation",role,products,{RichonlineMallCurrency::gold,inactive},activation_now,RichonlineInventoryDateVersion::original_2005,"activate-no-funds","fixture").status==RichonlineMallActivationStatus::insufficient_funds,"activation insufficient funds accepted");
        check(accounts.activate_mall_item("Activation",role,products,{RichonlineMallCurrency::gold,inactive},expiry,RichonlineInventoryDateVersion::original_2005,"activate-expired","fixture").status==RichonlineMallActivationStatus::expired,"expired activation accepted");
        accounts.dispatch("accounts.update",{{"role_id",role},{"expected",{{"gold",0.0}}},{"changes",{{"gold",100.0}}},{"reason","activation restore fixture"}});
        const auto result=accounts.activate_mall_item("Activation",role,products,{RichonlineMallCurrency::gold,inactive},activation_now,RichonlineInventoryDateVersion::original_2005,"activate-success","fixture");
        check(result.status==RichonlineMallActivationStatus::activated&&result.activated->new_key==active&&result.activated->charge==12.0&&result.role.at("gold")==88.0&&result.role.at("coins")==100.0,"activation fee/expiry/key mismatch");
        check(accounts.lobby_inventory("Activation",role,activation_now).equipment[5]==active&&database.count("SELECT count(*) FROM native_mall_activations")==1,"activation equipment/receipt incomplete");
        const auto replay=accounts.activate_mall_item("Activation",role,products,{RichonlineMallCurrency::gold,inactive},activation_now,RichonlineInventoryDateVersion::original_2005,"activate-success","fixture");
        check(replay.status==RichonlineMallActivationStatus::replayed&&replay.role.at("gold")==88.0,"activation replay charged twice");
        rejects([&]{accounts.activate_mall_item("Activation",role,products,{RichonlineMallCurrency::m_points,inactive},activation_now,RichonlineInventoryDateVersion::original_2005,"activate-success","fixture");},"mall_activation_operation_conflict");
    }
    std::cout<<"PASS NEW mall atomic M/gold debit, score, shared inventory, current replay state, ownership/conflict, rollback, reopen, explicit wire77, activation fee/expiry/equipment/audit rollback/replay and refusal paths\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
