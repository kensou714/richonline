// Exercise the standalone command entry point on independent fixture databases.
// This shares its implementation without exposing migration in the live server.
#define wmain date_migration_command
#include "../tools/richonline_inventory_date_migrate.cpp"
#undef wmain
#include <sstream>

namespace {
void test_check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class Action>void test_rejects(Action action,const char* message){try{action();}catch(const std::exception& error){test_check(error.what()==std::string_view(message),"unexpected refusal");return;}throw std::runtime_error("expected refusal");}
std::pair<int,std::string> command(std::vector<std::wstring> arguments){
    std::vector<wchar_t*> pointers;for(auto& argument:arguments)pointers.push_back(argument.data());
    std::ostringstream output;auto* prior=std::cout.rdbuf(output.rdbuf());auto* errors=std::cerr.rdbuf(output.rdbuf());
    const auto status=date_migration_command(static_cast<int>(pointers.size()),pointers.data());
    std::cout.rdbuf(prior);std::cerr.rdbuf(errors);return {status,output.str()};
}
std::int64_t scalar(sqlite3* db,const char* sql){Statement row(db,sql);test_check(row.row(),"scalar absent");return row.integer(0);}
Json snapshot(sqlite3* db,const char* sql){Statement row(db,sql);Json rows=Json::array();while(row.row())rows.push_back(row.record());return rows;}
RichonlineMailDelivery mail_fixture(std::uint32_t key,std::int64_t expiry){
    RichonlineMailRecord88 record{};record.opaque_kind=7;record.sender.opaque_actor_word=9;record.sender.opaque_actor_short=2;
    record.sender.opaque_padding={3,4};record.sender.name[0]='S';record.recipient.name[0]='R';
    record.recipient.opaque_actor_word=8;record.recipient.opaque_actor_short=3;record.recipient.opaque_padding={4,5};
    record.subject[0]='T';record.date_text[0]='2';record.time_text[0]='1';record.key={20,11};
    record.read_word=2;record.attachment_token=42;record.body[0]='B';return {record,key,expiry,"legacy-mail"};
}
}
int wmain(int argc,wchar_t** argv){try{
    test_check(argc==3,"verified compatible client and NEW resource root required");
    const auto client=std::filesystem::path(argv[1]);const auto resource_root=std::filesystem::path(argv[2]);
    const auto root=std::filesystem::absolute("native-server/build-auxiliary-ranking-20261009/fixtures/date-migration-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    const auto source=root/"original.sqlite3",migrated=root/"modern.sqlite3",rolled=root/"rollback.sqlite3";
    constexpr std::int64_t future=1893456000; //2030-01-01 UTC, authoritative legacy fixture expiry.
    constexpr std::int64_t historical=1514764800; //2018-01-01 UTC.
    constexpr std::int64_t now=1791504000; //2026-10-09 UTC.
    const auto old_item=richonline_inventory_key_from_expiry(0x1004,historical,RichonlineInventoryDateVersion::original_2005);
    const auto old_mail=richonline_inventory_key_from_expiry(0x1005,historical,RichonlineInventoryDateVersion::original_2005);
    const auto modern_item=richonline_inventory_key_from_expiry(old_item,future,RichonlineInventoryDateVersion::compat_2021_v1);
    const auto modern_mail=richonline_inventory_key_from_expiry(old_mail,future,RichonlineInventoryDateVersion::compat_2021_v1);
    const auto old_history=richonline_inventory_key_from_expiry(0x1006,historical,RichonlineInventoryDateVersion::original_2005);
    const auto delivery=mail_fixture(old_mail,future);std::int64_t role_id=0;Json immutable,roles_before,mail_evidence;
    {
        Storage store(source);const auto account=store.dispatch("accounts.create",{{"username","Migration"},{"password","test"}}).at("account");role_id=account.at("role_id").get<std::int64_t>();
        store.dispatch("accounts.update",{{"role_id",role_id},{"expected",{{"coins",account.at("coins")},{"gold",account.at("gold")},{"experience",account.at("experience")}}},{"changes",{{"coins",1234.0},{"gold",5678.0},{"experience",4321}}},{"reason","offline fixture"}});
        store.ensure_test_rp_certificate("Migration",now);store.deliver_mail("Migration",role_id,delivery);
        Database db(source,true);
        Statement item(db.db,"INSERT INTO lobby_inventory VALUES('Migration',?,?)");item.bind(1,old_item);item.bind(2,future);item.row();
        Statement equipment(db.db,"INSERT INTO lobby_equipment VALUES(?,4,?)");equipment.bind(1,role_id);equipment.bind(2,old_item);equipment.row();
        {Statement history(db.db,"INSERT INTO lobby_inventory VALUES('Migration',?,?)");history.bind(1,old_history);history.bind(2,historical);history.row();}
        execute(db.db,"INSERT INTO lobby_inventory VALUES('Migration',8,0);");
        // Deliberately seed a historical buggy key with authoritative2030 expiry.
        // This is test data, never a workaround accepted for a new purchase.
        execute(db.db,"CREATE TABLE native_mall_purchases(operation_id TEXT PRIMARY KEY,username TEXT,role_id INTEGER,request_key INTEGER,owned_key INTEGER,expires_at INTEGER,opaque_word0 INTEGER,opaque_word2 INTEGER,evidence TEXT,price REAL,score INTEGER,created_at INTEGER,date_version INTEGER) STRICT;");
        Statement receipt(db.db,"INSERT INTO native_mall_purchases VALUES('legacy-purchase','Migration',?,4100,?,?,7,9,'legacy fixture',1.0,10,100,2005)");receipt.bind(1,role_id);receipt.bind(2,old_item);receipt.bind(3,future);receipt.row();
        immutable=snapshot(db.db,"SELECT * FROM native_mall_purchases");roles_before=snapshot(db.db,"SELECT * FROM roles ORDER BY role_id");
        mail_evidence=snapshot(db.db,"SELECT operation_id,record_hex,original_hex,original_token,key_high,key_low FROM native_mail");
    }
    const auto original_hash=richonline_date_image_sha256(file_bytes(source));
    const auto planned=command({L"date-migrate",L"plan",source.wstring(),client.wstring()});
    test_check(planned.first==0&&Json::parse(planned.second).at("ready")==true,"dry run refused valid fixture");
    test_check(original_hash==richonline_date_image_sha256(file_bytes(source)),"dry run changed source");
    require_no_journal(source);
    {
        const auto writer=CreateFileW(source.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        test_check(writer!=INVALID_HANDLE_VALUE,"writer fixture open failed");
        const auto blocked=command({L"date-migrate",L"plan",source.wstring(),client.wstring()});CloseHandle(writer);
        test_check(blocked.first==1&&blocked.second.find("writer_active")!=std::string::npos,"active source writer accepted");
    }
    const auto copied=command({L"date-migrate",L"migrate-copy",source.wstring(),migrated.wstring(),client.wstring()});
    if(copied.first!=0)throw std::runtime_error("migrate copy failed: "+copied.second);test_check(original_hash==richonline_date_image_sha256(file_bytes(source)),"migration changed source");
    {
        Database db(migrated,false);
        test_check(metadata(db.db,"inventory_date_version","")==richonline_inventory_compatibility_id,"epoch not tagged");
        test_check(snapshot(db.db,"SELECT * FROM roles ORDER BY role_id")==roles_before,"wallet/experience/roles changed");
        test_check(snapshot(db.db,"SELECT * FROM native_mall_purchases")==immutable,"immutable receipt changed");
        test_check(snapshot(db.db,"SELECT operation_id,record_hex,original_hex,original_token,key_high,key_low FROM native_mail")==mail_evidence,"immutable mailbox bytes changed");
        test_check(scalar(db.db,"SELECT count(*) FROM inventory_key_aliases")==2,"aliases incomplete");
        Statement item(db.db,"SELECT expires_at FROM lobby_inventory WHERE username='Migration' AND encoded_item=?");item.bind(1,modern_item);test_check(item.row()&&item.integer(0)==future,"inventory expiry/key lost");
        Statement equipment(db.db,"SELECT encoded_item FROM lobby_equipment WHERE role_id=? AND slot=4");equipment.bind(1,role_id);test_check(equipment.row()&&equipment.integer(0)==modern_item,"equipment key stale");
        test_check(scalar(db.db,"SELECT encoded_item FROM lobby_equipment WHERE slot=13")==13,"PK certificate equipment changed");
        test_check(scalar(db.db,"SELECT expires_at FROM lobby_inventory WHERE encoded_item=13")==now+30*24*60*60,"PK certificate expiry changed");
        test_check(scalar(db.db,"SELECT granted_item FROM native_mail")==modern_mail&&scalar(db.db,"SELECT original_token FROM native_mail")==42,"mail grant or original token changed");
        test_check(scalar(db.db,"SELECT original_key FROM inventory_date_mail_receipts")==old_mail,"mail original grant missing");
        {Statement history(db.db,"SELECT expires_at FROM lobby_inventory WHERE encoded_item=?");history.bind(1,old_history);test_check(history.row()&&history.integer(0)==historical,"historical item revived");}
        test_check(scalar(db.db,"SELECT expires_at FROM lobby_inventory WHERE encoded_item=8")==0,"no-date untimed item changed");
    }
    const auto rollback=command({L"date-migrate",L"rollback-copy",migrated.wstring(),rolled.wstring()});test_check(rollback.first==0,"new copy rollback failed");
    {Database db(rolled,false);test_check(metadata(db.db,"inventory_date_version","original-2005")=="original-2005"&&snapshot(db.db,"SELECT * FROM roles ORDER BY role_id")==roles_before,"rollback did not restore original state");}
    const auto overwrite=command({L"date-migrate",L"migrate-copy",source.wstring(),migrated.wstring(),client.wstring()});test_check(overwrite.first==1,"destination overwrite allowed");
    {
        new_file(std::filesystem::path(migrated.wstring()+L"-wal"));
        const auto blocked=command({L"date-migrate",L"rollback-copy",migrated.wstring(),(root/"wal-refused.sqlite3").wstring()});
        test_check(blocked.first==1&&blocked.second.find("journal_present")!=std::string::npos,"WAL rollback allowed");
        std::filesystem::remove(std::filesystem::path(migrated.wstring()+L"-wal"));
    }
    {
        Storage store(migrated);const auto catalog=RichonlineMallCatalog::load(resource_root);
        RichonlineMallPurchase replay{"legacy-purchase",{0x1004},{old_item,future,7,9,"legacy fixture"},RichonlineInventoryDateVersion::compat_2021_v1};
        const auto result=store.purchase_mall_item("Migration",role_id,catalog,replay,now);
        test_check(result.status==RichonlineMallPurchaseStatus::replayed&&result.granted->owned_key==modern_item&&result.role.at("coins")==1234.0,"alias purchase replay charged or lost key");
        test_check(store.deliver_mail("Migration",role_id,delivery)==RichonlineMailMutation::duplicate,"migrated delivery replay rejected");
        auto different=delivery;different.granted_item=modern_mail;test_rejects([&]{store.deliver_mail("Migration",role_id,different);},"mail_delivery_operation_conflict");
        const auto claimed=store.claim_mail("Migration",role_id,{delivery.record.key,42},now);
        test_check(claimed.status==RichonlineMailMutation::changed&&claimed.granted_item==modern_mail,"claim did not grant migrated key");
        test_check(store.deliver_mail("Migration",role_id,delivery)==RichonlineMailMutation::duplicate,"claimed migrated delivery replay rejected");
    }
    const auto changed=command({L"date-migrate",L"rollback-copy",migrated.wstring(),(root/"changed-refused.sqlite3").wstring()});
    test_check(changed.first==1&&changed.second.find("changed_since_commit")!=std::string::npos,"rollback discarded postmigration transactions");
    // Independent malformed-source fixtures exercise preflight boundaries.
    const auto bad=root/"unresolved.sqlite3";{Database original(source,false);backup(original.db,bad);}
    {
        Database db(bad,true);execute(db.db,"UPDATE lobby_inventory SET expires_at=0 WHERE encoded_item!=13;");
        test_check(!plan(db.db,now).report.at("ready").get<bool>(),"dated key without expiry accepted");
    }
    const auto orphan=root/"orphan.sqlite3";{Database original(source,false);backup(original.db,orphan);}
    {
        Database db(orphan,true);execute(db.db,"DELETE FROM lobby_inventory WHERE encoded_item!=13;");
        test_check(!plan(db.db,now).report.at("ready").get<bool>(),"orphan equipment accepted");
    }
    const auto conflict=root/"collision.sqlite3";{Database original(source,false);backup(original.db,conflict);}
    {
        Database db(conflict,true);Statement seed(db.db,"INSERT INTO lobby_inventory VALUES('Migration',?,?)");seed.bind(1,modern_item);seed.bind(2,future);seed.row();
        test_check(!plan(db.db,now).report.at("ready").get<bool>(),"overlapping inventory target accepted");
    }
    const auto after=command({L"date-migrate",L"plan",migrated.wstring(),client.wstring()});test_check(after.first==1,"second migration accepted modern source");
    std::cout<<"PASS offline dry-run/source preservation/writer refusal, new-copy backup/migration/rollback, wallet/experience/history, inventory/equipment/mail/PK13, immutable alias replays, claim, collisions/orphans/unresolved, and changed/WAL rollback refusal\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
