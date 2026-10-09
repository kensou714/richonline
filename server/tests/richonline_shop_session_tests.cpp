#include "richonline_boss_session.hpp"
#include "richonline_shop_catalog.hpp"
#include "storage.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <algorithm>
#include <iostream>
#include <thread>

namespace {
using namespace richnet;
constexpr std::uint16_t game_id=0x1234,calendar=0x4567;
void check(bool ok,const char* reason) { if(!ok) throw std::runtime_error(reason); }
std::uint16_t opcode(const Bytes& value) { return static_cast<std::uint16_t>(read_le(View(value).first(2))); }
Bytes request(std::uint16_t op,std::uint16_t counter,std::uint32_t value=0,std::size_t width=0) {
    Bytes bytes; append_le(bytes,op,2); append_le(bytes,counter,2);
    if(width) append_le(bytes,value,width);
    return bytes;
}
Bytes order(std::uint16_t op,std::int8_t index) {
    auto bytes=request(op,calendar+2,static_cast<std::uint8_t>(index),1); bytes.push_back(0xcc); return bytes;
}
Bytes refresh() { return request(0x35,calendar+2); }
std::vector<Bytes> decode(const std::vector<Bytes>& frames) {
    std::vector<Bytes> plain;
    for(const auto& wire:frames) {
        const auto frame=decode_frame(wire,{Channel::game_s2c,{},ClientVersion::richonline});
        if(frame.wire_type==1) { check(frame.payload.empty(),"shop_admission_ack_payload"); continue; }
        const auto envelope=decode_envelope(frame,ClientVersion::richonline);
        check(envelope.inner_type==7 && envelope.mode==-2,"shop_session_envelope_changed");
        plain.push_back(decode_inner(envelope.encoded));
    }
    return plain;
}
struct Flow {
    std::filesystem::path database;
    Storage storage;
    std::int64_t role;
    std::unique_ptr<GameSession> session;
    std::vector<GameGoldCharge> debits;
    std::uint32_t card_price;
    std::vector<Bytes> stock_packets;
    unsigned stock_draws=0,stock_generations=0;
    double starting_gold;
    const GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    Flow(const std::filesystem::path& resources,const std::filesystem::path& db,std::uint32_t initial_reserve,bool varied_stock=false)
        :database(db),storage(db),role(storage.dispatch("accounts.create",{{"username","shop-session"},{"password","isolated"}})
            .at("account").at("role_id").get<std::int64_t>()),
         card_price(RichonlineShopCatalog::load(resources,"BS_1_1.emp").price(1038)) {
        const auto& package=legacy_richonline_map_package();
        const auto stage=package.load_stage(resources,0);
        starting_gold=stage.pawn_gold+initial_reserve;
        sql("UPDATE roles SET gold="+std::to_string(starting_gold)+",coins=789,bank=456");
        const auto topology=load_richonline_road_topology(resources/"Map/BS_1_1.emp");
        const auto& cell=topology.cell(117);
        check(cell.static_type==10 && cell.property_ref==-1 &&
            std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](auto edge){return edge.has_value();})==2,
            "real_shop_session_cell_changed");
        // Cell 117 has two roads, but unlike junction 178 they are not necessarily vertical.
        // Select an actual adjacent spawn/heading and verify the complete one-step route.
        std::optional<std::pair<std::int16_t,std::uint8_t>> approach;
        for(std::uint8_t direction=0;direction<4 && !approach;++direction) if(cell.neighbors[direction]) {
            const auto adjacent=*cell.neighbors[direction];
            const auto heading=static_cast<std::uint8_t>((direction+2U)%4U);
            check(topology.cell(adjacent).neighbors[heading]==117,"shop_fixture_road_not_reciprocal");
            const auto route=build_richonline_route(topology,{adjacent,heading,1,{}},
                [](std::size_t){return std::size_t{0};});
            if(route.landings==std::vector<std::int16_t>{117}) approach=std::pair{adjacent,heading};
        }
        check(approach.has_value(),"shop_fixture_has_no_verified_one_step_approach");
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {game_id,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,approach->first,approach->second,{5,5,5,5,5,5,5,5,5,5},0xb1},{-1,236,1,{},0xc1}}},
            {game_id,calendar,1,{{20000,432,card_price},{100000,0,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        auto& extension=startup.room.description.extension; extension.resize(88);
        std::copy(stage.map_name.begin(),stage.map_name.end(),extension.begin());
        std::copy(stage.signature.begin(),stage.signature.end(),extension.begin()+32);
        RichonlineBossSessionPolicy policy{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [](std::size_t){return std::size_t{0};},RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}}};
        if(varied_stock) {
            const auto pool=RichonlineShopCatalog::load(resources,"BS_1_1.emp").offers().size();
            check(pool>18,"stock_rng_fixture_overlaps_movement_domain");
            policy.random=[this,pool](std::size_t bound) {
                if(bound<=pool && bound>pool-12) {
                    if(bound==pool)++stock_generations;
                    ++stock_draws;
                    return static_cast<std::size_t>(stock_generations-1)%bound;
                }
                return std::size_t{0};
            };
        }
        policy.payment=RichonlineBossSessionPolicy::AccountPayment{starting_gold,"shop-test",
            [this](const GameGoldCharge& charge) {
                debits.push_back(charge); return storage.consume_game_gold("shop-session",role,charge);
            },{false,false}};
        auto plan=make_richonline_boss_session(resources,startup,package,policy,
            std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources)),{});
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& value)->std::optional<RichonlineStartupPlan> {
                return value==admission ? std::optional{plan} : std::nullopt;
            },[](std::size_t size){return Bytes(size,0x91);}));
        const auto joined=decode(session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(joined.size()==1 && opcode(joined[0])==0x4000,"shop_session_admission_failed");
        send({0,0}); send(request(0x11,calendar+1,235,2)); send(request(0x10,calendar+2,0,4));
        const auto opened=send(request(0x11,calendar+2,117,2));
        check(opened.size()==2 && opcode(opened[0])==0x4013 && opcode(opened[1])==0x4030 &&
            opened[1].size()==77 && opened[1].back()==0,"shared_session_shop_did_not_open");
    }
    void sql(const std::string& query) {
        sqlite3* db=nullptr; const auto name=database.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"shop_sql_open");
        const auto rc=sqlite3_exec(db,query.c_str(),nullptr,nullptr,nullptr); sqlite3_close(db);
        check(rc==SQLITE_OK,"shop_fixture_sql_failed");
    }
    int count(const char* query) {
        sqlite3* db=nullptr; const auto name=database.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(name.c_str()),&db)==SQLITE_OK,"shop_count_open");
        sqlite3_stmt* statement=nullptr;
        check(sqlite3_prepare_v2(db,query,-1,&statement,nullptr)==SQLITE_OK,"shop_count_prepare");
        check(sqlite3_step(statement)==SQLITE_ROW,"shop_count_row");
        const auto result=sqlite3_column_int(statement,0); sqlite3_finalize(statement); sqlite3_close(db); return result;
    }
    double gold() { return storage.roles_for_username("shop-session").at(0).at("gold").get<double>(); }
    void persistent_funds(double expected) {
        const auto account=storage.roles_for_username("shop-session").at(0);
        check(account.at("gold")==expected && account.at("coins")==789 && account.at("bank")==456,
            "shop_charged_wrong_persistent_currency");
    }
    std::vector<Bytes> send(const Bytes& plain) {
        auto result=decode(session->feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        for(const auto& value:result)if(opcode(value)==0x4030)stock_packets.push_back(value);
        return result;
    }
    void check_closed_and_progress(const std::vector<Bytes>& result) {
        check(result.size()==4 && result[0]==Bytes({0x31,0x40,0x34,0x12,0xff}) &&
            opcode(result[1])==0x4010 && result[1][4]==1 && session->state()==GameState::admitted,
            "shop_close_did_not_resume_boss_turn");
        const auto completed=send(request(0x11,calendar+3,234,2));
        check(completed.size()==3 && opcode(completed[1])==0x4010 && completed[1][4]==0,
            "shop_refusal_did_not_recover_next_human_turn");
    }
};
void shared_random_stock(const std::filesystem::path& resources,const std::filesystem::path& root) {
    Flow flow(resources,root/"random-stock.sqlite3",2000,true);
    const auto catalog=RichonlineShopCatalog::load(resources,"BS_1_1.emp");
    check(flow.stock_generations==1 && flow.stock_draws==12,"session_shop_did_not_use_shared_rng_on_entry");
    check(flow.stock_packets.size()==1,"entry_stock_not_recorded");
    for(unsigned refresh_index=0;refresh_index<5;++refresh_index) {
        const auto before=flow.stock_packets.back();
        const auto response=flow.send(refresh());
        check(response.size()==1 && response[0].back()==1 && flow.stock_generations==refresh_index+2 &&
            flow.stock_draws==12*(refresh_index+2),"session_refresh_did_not_draw_new_shared_stock");
        check(!std::equal(before.begin()+4,before.begin()+76,response[0].begin()+4),"refresh_only_changed_flag_not_stock");
        flow.persistent_funds(flow.starting_gold-250*(refresh_index+1));
    }
    for(const auto& packet:flow.stock_packets) {
        check(packet.size()==77,"random_stock_packet_size_wrong");
        std::vector<std::int16_t> ids;
        for(std::size_t index=0;index<12;++index) {
            const auto offset=4+6*index;
            const RichonlineShopOffer offer{static_cast<std::int16_t>(read_le(View(packet).subspan(offset,2))),
                static_cast<std::int16_t>(read_le(View(packet).subspan(offset+2,2)))};
            check(std::find(catalog.offers().begin(),catalog.offers().end(),offer)!=catalog.offers().end(),
                "random_stock_not_in_actual_map_and_prop_catalog");
            check(std::find(ids.begin(),ids.end(),offer.card_id)==ids.end(),"random_stock_duplicate_card");
            ids.push_back(offer.card_id);
            check(packet[offset+4]==0 && packet[offset+5]==255,"random_stock_changed_compatibility_fields");
        }
    }
    const auto draws=flow.stock_draws;
    flow.check_closed_and_progress(flow.send(refresh()));
    check(flow.stock_draws==draws && flow.debits.size()==5,"exhausted_refresh_generated_or_charged_stock");
    std::cout<<"verified shared RNG six independent stocks, 72 bounded draws, 12 unique resource offers each\n";
}
void success_and_limit(const std::filesystem::path& resources,const std::filesystem::path& root) {
    Flow flow(resources,root/"success.sqlite3",2000);
    for(unsigned i=0;i<5;++i) {
        const auto reply=flow.send(refresh());
        check(reply.size()==1 && opcode(reply[0])==0x4030 && reply[0].size()==77 && reply[0].back()==1,
            "shop_refresh_success_wire_wrong");
        check(flow.debits.size()==i+1 && flow.debits.back().amount==250 &&
            flow.debits.back().operation_id=="shop-test:shop:"+std::to_string(i+1),"shop_refresh_charge_not_250_or_unique");
        flow.persistent_funds(flow.starting_gold-250*(i+1));
    }
    // Initial tickets equal one card's exact price. Five gold refreshes must leave this purchase possible.
    const auto bought=flow.send(order(0x30,0));
    check(bought==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0}},"refresh_spent_tickets_or_exact_balance_purchase_failed");
    const auto sold=flow.send(order(0x31,0));
    check(sold==std::vector<Bytes>{{0x32,0x40,0x34,0x12,0}},"shared_session_sale_failed");
    flow.persistent_funds(flow.starting_gold-1250);
    flow.check_closed_and_progress(flow.send(refresh()));
    check(flow.send(refresh()).empty() && flow.debits.size()==5,"retired_refresh_debited_again");
    check(flow.count("SELECT count(*) FROM audit WHERE source='native-game-charge'")==5 &&
        flow.count("SELECT count(*) FROM operations WHERE source='native-game-charge'")==5,"refresh_audit_not_once_per_charge");
}
void insufficient(const std::filesystem::path& resources,const std::filesystem::path& root) {
    Flow reserve(resources,root/"reserve.sqlite3",300);
    check(reserve.send(refresh()).size()==1,"first_floor_reserve_refresh_failed");
    reserve.check_closed_and_progress(reserve.send(refresh()));
    check(reserve.debits.size()==1,"insufficient_shared_reserve_reached_account_debit");
    reserve.persistent_funds(reserve.starting_gold-250);
    Flow account(resources,root/"account.sqlite3",2000); account.sql("UPDATE roles SET gold=249");
    account.check_closed_and_progress(account.send(refresh()));
    check(account.debits.size()==1 && account.send(refresh()).empty(),"account_refusal_replayed_or_disconnected");
    account.persistent_funds(249);
    check(account.count("SELECT count(*) FROM audit WHERE source='native-game-charge'")==0,"refused_refresh_audited_as_success");
}
void timeout(const std::filesystem::path& resources,const std::filesystem::path& root) {
    Flow flow(resources,root/"timeout.sqlite3",2000);
    std::this_thread::sleep_for(std::chrono::milliseconds{10100});
    flow.check_closed_and_progress(decode(flow.session->poll()));
    check(flow.send(refresh()).empty() && flow.debits.empty(),"timed_out_refresh_charged");
    flow.persistent_funds(flow.starting_gold);
}
void audit_rollback(const std::filesystem::path& resources,const std::filesystem::path& root) {
    Flow flow(resources,root/"rollback.sqlite3",2000);
    flow.sql("CREATE TRIGGER reject_refresh BEFORE INSERT ON audit WHEN NEW.source='native-game-charge' BEGIN SELECT RAISE(ABORT,'shop-test'); END");
    std::vector<Bytes> emitted; bool rejected=false;
    try { emitted=flow.send(refresh()); } catch(const StorageError&) { rejected=true; }
    check(rejected && emitted.empty() && flow.session->state()==GameState::closed,
        "failed_audit_emitted_refresh_success_or_kept_uncertain_session");
    flow.persistent_funds(flow.starting_gold);
    check(flow.count("SELECT count(*) FROM audit WHERE source='native-game-charge'")==0 &&
        flow.count("SELECT count(*) FROM operations WHERE source='native-game-charge'")==0,"failed_refresh_did_not_rollback_database");
}
void persistent_replay(const std::filesystem::path& resources,const std::filesystem::path& root) {
    Flow flow(resources,root/"replay.sqlite3",2000);
    const auto prior=flow.storage.consume_game_gold("shop-session",flow.role,{250,"shop-test:shop:1","shop refresh"});
    check(prior.status==GameChargeStatus::success && !prior.replayed,"shop_replay_fixture_failed");
    std::vector<Bytes> emitted; bool rejected=false;
    try { emitted=flow.send(refresh()); }
    catch(const CodecError& error) { rejected=std::string(error.what())=="richonline_payment_recovery_required"; }
    check(rejected && emitted.empty() && flow.session->state()==GameState::closed,
        "persisted_refresh_replay_fabricated_success");
    flow.persistent_funds(flow.starting_gold-250);
    check(flow.count("SELECT count(*) FROM audit WHERE source='native-game-charge'")==1,
        "persisted_refresh_replay_debited_again");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"NEW_resource_root_required"); const std::filesystem::path resources(argv[1]);
        const auto root=std::filesystem::temp_directory_path()/("shop-session-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root);
        shared_random_stock(resources,root);
        success_and_limit(resources,root); insufficient(resources,root); timeout(resources,root);
        audit_rollback(resources,root); persistent_replay(resources,root);
        std::filesystem::remove_all(root);
        std::cout<<"PASS shared NEW shop session, SQLite refresh, currency separation, timeout, refusal and audit rollback\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
