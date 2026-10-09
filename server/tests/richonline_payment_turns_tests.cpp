#include "richonline_motion_card.hpp"
#include "storage.hpp"
#include "original_map.hpp"
#include <sqlite3.h>
#include <windows.h>
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t game_id=0x1234,calendar=0x4567;
void check(bool ok,const char* reason) {if(!ok)throw std::runtime_error(reason);}
std::uint16_t opcode(const Bytes& b){return static_cast<std::uint16_t>(read_le(View(b).first(2)));}
Bytes req(std::uint16_t op,std::uint16_t counter,std::uint32_t value,std::size_t width=2){
    Bytes b;append_le(b,op,2);append_le(b,counter,2);append_le(b,value,width);return b;
}
Bytes paid(std::uint8_t die){auto b=req(22,calendar+2,die,1);b.push_back(0xcc);return b;}
RichonlineRoadTopology roads(bool interrupt){
    OriginalEmp emp{3,30,1,{}, {},Bytes(8+68*30,0xff),8,8+64*30,0,0};
    for(std::size_t i=0;i<30;++i)if(i<=12 || i>=20)emp.payload[emp.terrain_offset+64*i]=8;
    if(interrupt)emp.payload[emp.tile_types_offset+4*5]=67;
    return richonline_road_topology(emp);
}
std::vector<Bytes> decode(const std::vector<Bytes>& frames){
    std::vector<Bytes> result;
    for(const auto& b:frames){const auto f=decode_frame(b,{Channel::game_s2c,{},ClientVersion::richonline});
        if(f.wire_type!=1)result.push_back(decode_inner(decode_envelope(f,ClientVersion::richonline).encoded));}
    return result;
}
struct Flow {
    std::filesystem::path db_path;
    Storage storage;
    std::int64_t role;
    std::shared_ptr<RichonlineGameLedger> ledger;
    std::shared_ptr<RichonlineGamePayment> payment;
    std::shared_ptr<RichonlineBossCards> cards;
    std::unique_ptr<GameSession> session;
    unsigned debit_calls=0;
    unsigned random_calls=0;
    bool control_after_landing=false;
    std::chrono::steady_clock::time_point now{};
    std::vector<std::string> operations;
    const GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    Flow(const std::filesystem::path& resources,const std::filesystem::path& db,int gold,
        std::uint32_t reserve,bool interrupted=false,bool database_replay=false,bool broken_log=false,
        RichonlinePaidDiceEquipment equipment={false,false})
        :db_path(db),storage(db),role(storage.dispatch("accounts.create",{{"username","paid-turn"},{"password","test-only"}})
            .at("account").at("role_id").get<std::int64_t>()),
         ledger(std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{{1000,200,150,reserve},{5000,400,0,{}}})) {
        sql("UPDATE roles SET gold="+std::to_string(gold));
        const auto charges=load_richonline_gold_charges(resources/"Data/GoldCharge.kpd");
        if(database_replay)storage.consume_game_gold("paid-turn",role,
            {300,"isolated-session:turn=2:counter=17769:paid-die:face=2","paid controlled die face=2"});
        payment=std::make_shared<RichonlineGamePayment>(ledger,0,charges,[this](const GameGoldCharge& charge){
            ++debit_calls;operations.push_back(charge.operation_id);return storage.consume_game_gold("paid-turn",role,charge);
        });
        cards=std::make_shared<RichonlineBossCards>(
            std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources)),game_id,
            RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {game_id,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,3,3,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,27,1,{},0xc1}}},
            {game_id,calendar,1,{{1000,200,150},{5000,400,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [this](std::size_t){++random_calls;return std::size_t{0};},[this](const RichonlineLandingContext& ctx){
                RichonlineLandingResult result{{req(0x4013,game_id,static_cast<std::uint16_t>(ctx.position))},RichonlineLandingProgress::complete};
                if(control_after_landing && ctx.actor_slot==0) {
                    auto next=ctx.actor_status;next.sleepwalking=3;
                    result.status_change=RichonlineLandingStatusChange{ctx.actor_status,next};
                }
                return result;
            },[](View)->RichonlineLandingResult{throw CodecError("unexpected_paid_event");}};
        rules.cards=cards;rules.payment=payment;rules.payment_operation_prefix="isolated-session";
        rules.payment_equipment=equipment;
        rules.now=[this]{return now;};
        rules.motion_cards=std::make_shared<RichonlineMotionCardRules>(RichonlineMotionCardRules::load(resources));
        auto plan=make_richonline_boss_turns(startup,roads(interrupted),std::move(rules));
        const GameLogSink diagnostic=[broken_log](const std::string&) {
            if (broken_log) throw std::runtime_error("log_write_failed");
        };
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& a)->std::optional<RichonlineStartupPlan>{
                return a==admission?std::optional{plan}:std::nullopt;
            },[](std::size_t size){return Bytes(size,0x91);},diagnostic),diagnostic);
        decode(session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        send({0,0});send(req(0x11,calendar+1,26));
    }
    void sql(const std::string& query){sqlite3* db=nullptr;const auto path=db_path.u8string();
        check(sqlite3_open(reinterpret_cast<const char*>(path.c_str()),&db)==SQLITE_OK,"paid_sql_open");
        const auto rc=sqlite3_exec(db,query.c_str(),nullptr,nullptr,nullptr);sqlite3_close(db);check(rc==SQLITE_OK,"paid_sql_failed");}
    double gold(){return storage.roles_for_username("paid-turn").at(0).at("gold").get<double>();}
    std::vector<Bytes> send(const Bytes& plain){return decode(session->feed(encode_frame(
        richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),{Channel::game_c2s,{},ClientVersion::richonline})));}
};
void random_dice_charge_and_retry(const std::filesystem::path& resources,const std::filesystem::path& root){
    Flow f(resources,root/"random-three.sqlite3",1000,1000);
    check(f.send(req(0x14,calendar+2,3)).empty() && f.gold()==1000,"selection_charged_before_roll");
    const auto roll=req(0x10,calendar+2,0,4);const auto response=f.send(roll);
    check(response.size()==1 && opcode(response[0])==0x4011 && response[0][6]==3 && response[0][7]==3 &&
        read_le(View(response[0]).subspan(24,4))==240 && f.gold()==760 && f.payment->reserve()==760 && f.debit_calls==1,
        "random_three_dice_fee_or_route_wrong");
    const auto random=f.random_calls;
    check(f.send(roll).empty() && f.random_calls==random && f.debit_calls==1 && f.gold()==760,
        "duplicate_random_roll_rerolled_or_charged");
    f.send(req(0x11,calendar+2,6));
    check(f.send(roll).empty() && f.debit_calls==1,"late_random_roll_recharged_on_boss_turn");
    f.send(req(0x11,calendar+3,25));
    check(f.send(roll).empty() && f.debit_calls==1,"old_random_roll_recharged_next_local_turn");
    const auto next=f.send(req(0x10,calendar+4,0,4));
    check(next[0][6]==3 && f.gold()==520 && f.debit_calls==2,"new_turn_random_dice_not_charged_once");
}
void random_dice_refusal_and_free_vehicle(const std::filesystem::path& resources,const std::filesystem::path& root){
    for(const bool account_refusal:{false,true}){
        Flow f(resources,root/(account_refusal?"random-account-poor.sqlite3":"random-reserve-poor.sqlite3"),
            account_refusal?0:1000,account_refusal?1000:100);
        f.send(req(0x14,calendar+2,2));const auto refused=f.send(req(0x10,calendar+2,0,4));
        check(refused==std::vector<Bytes>{{0x0b,0x40,0x34,0x12,1}} && f.session->state()==GameState::admitted &&
            f.gold()==(account_refusal?0:1000),"random_dice_refusal_failed_recovery");
        f.send(req(0x14,calendar+2,1));const auto single=f.send(req(0x10,calendar+2,0,4));
        check(single[0][6]==1 && read_le(View(single[0]).subspan(24,4))==0,"free_single_after_refusal_unavailable");
    }
    for(const auto& [vehicle,count,charge]:std::array<std::tuple<RichonlineDiceVehicle,std::uint8_t,std::uint32_t>,3>{{
        {RichonlineDiceVehicle::motorcycle,2,0},{RichonlineDiceVehicle::motorcycle,3,160},{RichonlineDiceVehicle::car,3,0}}}){
        Flow f(resources,root/("vehicle-"+std::to_string(static_cast<int>(vehicle))+"-"+std::to_string(count)+".sqlite3"),
            1000,1000,false,false,false,{true,true,vehicle});
        f.send(req(0x14,calendar+2,count));const auto response=f.send(req(0x10,calendar+2,0,4));
        check(response[0][6]==count && read_le(View(response[0]).subspan(24,4))==charge && f.gold()==1000-charge &&
            f.payment->reserve()==1000-charge,"random_vehicle_fee_not_used");
    }
}
void random_route_and_override_do_not_mischarge(const std::filesystem::path& resources,const std::filesystem::path& root){
    Flow invalid(resources,root/"random-bad-route.sqlite3",1000,1000,true);
    invalid.send(req(0x14,calendar+2,3));
    bool failed=false;try{invalid.send(req(0x10,calendar+2,0,4));}catch(const CodecError&){failed=true;}
    check(failed && invalid.debit_calls==0 && invalid.gold()==1000,"random_route_charged_before_validation");
    Flow fixed(resources,root/"random-turtle.sqlite3",1000,1000);fixed.send(req(0x14,calendar+2,3));
    fixed.cards->commit_inventory(fixed.cards->prepare_add(1039));auto turtle=req(104,calendar+2,0);
    turtle.insert(turtle.end(),{0,0xcc});fixed.send(turtle);
    const auto moved=fixed.send(req(0x10,calendar+2,0,4));
    check(moved[0][6]==1 && read_le(View(moved[0]).subspan(24,4))==0 && fixed.debit_calls==0 && fixed.gold()==1000,
        "forced_single_step_charged_three_dice");
    Flow controlled(resources,root/"random-controlled.sqlite3",1000,1000);controlled.send(req(0x14,calendar+2,3));
    controlled.cards->commit_inventory(controlled.cards->prepare_add(1038));auto choose=req(103,calendar+2,0);
    choose.insert(choose.end(),{2,0xcc,0,0,0,0});const auto selected=controlled.send(choose);
    check(selected.back()[6]==1 && read_le(View(selected.back()).subspan(24,4))==0 && controlled.debit_calls==0,
        "controlled_card_charged_random_dice");
}
void automatic_multi_dice_recovers_without_waiting_for_ui(const std::filesystem::path& resources,const std::filesystem::path& root){
    for(const unsigned scenario:std::array<unsigned,4>{0,1,2,3}){
        const auto motorcycle=scenario==1;
        Flow f(resources,root/("auto-dice-"+std::to_string(scenario)+".sqlite3"),1000,1000,false,false,false,
            {false,false,motorcycle?RichonlineDiceVehicle::motorcycle:RichonlineDiceVehicle::walking});
        f.send(req(0x14,calendar+2,3));f.send(req(0x10,calendar+2,0,4));
        f.control_after_landing=true;f.send(req(0x11,calendar+2,6));f.send(req(0x11,calendar+3,25));
        auto before=f.ledger->snapshot(0);auto changed=before.funds;
        changed.reserve=scenario==2?200U:scenario==3?1000U:100U;f.ledger->commit(0,before,changed);
        if(scenario==3)f.sql("UPDATE roles SET gold=0");
        const auto gold=f.gold();const auto calls=f.random_calls;const auto debits=f.debit_calls;
        f.now+=std::chrono::seconds{30};const auto automatic=decode(f.session->poll());
        const auto expected_count=static_cast<std::uint8_t>(motorcycle || scenario==2?2:1);
        const auto expected_fee=scenario==2?160U:0U;
        check(automatic.size()==1 && opcode(automatic[0])==0x4011 && automatic[0][6]==expected_count &&
            automatic[0][7]==expected_count && read_le(View(automatic[0]).subspan(24,4))==expected_fee,
            "automatic_multi_dice_refusal_stalled_or_charged_wrong_capacity");
        check(f.gold()==gold-expected_fee && f.payment->reserve()==*changed.reserve-expected_fee &&
            f.debit_calls==debits+(scenario>=2?1U:0U),"automatic_fallback_overspent_or_debited_free_capacity");
        check(f.random_calls==calls+(scenario==3?3U:expected_count),"automatic_account_refusal_rerolled_faces");
        const auto after=f.random_calls;
        check(f.send(req(0x10,calendar+4,0,4)).empty() && f.random_calls==after,
            "automatic_late_client_roll_restarted_movement");
        check(f.send(req(0x14,calendar+4,expected_count)).empty(),"automatic_ui_downgrade_disconnected_while_moving");
        f.send(req(0x11,calendar+4,6+expected_count));
        check(f.session->state()==GameState::admitted,"automatic_fallback_could_not_finish_move");
    }
}
void random_database_failure_and_replay_are_atomic(const std::filesystem::path& resources,const std::filesystem::path& root){
    Flow broken(resources,root/"random-db-error.sqlite3",1000,1000);broken.send(req(0x14,calendar+2,2));
    broken.sql("CREATE TRIGGER fail_charge BEFORE INSERT ON audit WHEN NEW.source='native-game-charge' BEGIN SELECT RAISE(ABORT,'injected'); END");
    bool failed=false;try{broken.send(req(0x10,calendar+2,0,4));}catch(const StorageError&){failed=true;}
    check(failed && broken.gold()==1000 && broken.payment->reserve()==1000,"random_database_failure_partly_committed");
    Flow replay(resources,root/"random-replay.sqlite3",1000,1000);replay.send(req(0x14,calendar+2,2));
    replay.storage.consume_game_gold("paid-turn",replay.role,
        {160,"isolated-session:turn=2:counter=17769:random-dice:count=2","random dice count=2"});
    failed=false;try{replay.send(req(0x10,calendar+2,0,4));}catch(const CodecError& e){
        failed=std::string(e.what())=="richonline_boss_random_dice_recovery_required";
    }
    check(failed && replay.gold()==840 && replay.payment->reserve()==1000,"random_restart_replay_charged_again");
}
void charge_moves_once(const std::filesystem::path& resources,const std::filesystem::path& root){
    Flow f(resources,root/"success.sqlite3",1000,1000);
    const auto before=f.ledger->snapshot(0).funds;const auto response=f.send(paid(2));
    check(response.size()==1 && opcode(response[0])==0x4011 && response[0][8]==2 &&
        read_le(View(response[0]).subspan(24,4))==300,"paid_route_or_charge_field_wrong");
    check(f.gold()==700 && f.payment->reserve()==700 && f.debit_calls==1,"paid_charge_not_conserved");
    const auto after=f.ledger->snapshot(0).funds;
    check(after.cash==before.cash && after.deposit==before.deposit && after.tickets==before.tickets,"paid_wrong_currency");
    check(f.send(paid(2)).empty() && f.gold()==700 && f.debit_calls==1,"duplicate_paid_moved_or_debited");
    const auto done=f.send(req(0x11,calendar+2,5));check(done.size()==4,"paid_route_not_completed");
    check(f.send(paid(2)).empty() && f.debit_calls==1,"old_counter_paid_replayed");
    check(f.operations.at(0)=="isolated-session:turn=2:counter=17769:paid-die:face=2","paid_operation_not_stable");
}
void refusal_keeps_turn(const std::filesystem::path& resources,const std::filesystem::path& root){
    for(const bool account_refusal:{false,true}){
        Flow f(resources,root/(account_refusal?"account-poor.sqlite3":"reserve-poor.sqlite3"),account_refusal?0:1000,account_refusal?300:200);
        const auto response=f.send(paid(2));
        check(response==std::vector<Bytes>{{0x0b,0x40,0x34,0x12,1}} && f.session->state()==GameState::admitted,
            "payment_refusal_did_not_recover_same_session");
        check(f.gold()==(account_refusal?0:1000) && f.payment->reserve()==(account_refusal?300U:200U),"refusal_changed_balance");
        check(f.send(paid(3))==response,"retry_other_die_after_refusal_failed");
        const auto ordinary=f.send(req(0x10,calendar+2,0,4));
        check(ordinary.size()==1 && ordinary[0][8]==1 && read_le(View(ordinary[0]).subspan(24,4))==0,
            "refused_payment_changed_turn_or_ordinary_charge");
    }
}
void invalid_route_precedes_debit(const std::filesystem::path& resources,const std::filesystem::path& root){
    Flow f(resources,root/"bad-route.sqlite3",1000,1000,true);
    try{f.send(paid(2));throw std::runtime_error("invalid_paid_route_accepted");}
    catch(const CodecError& e){check(std::string(e.what())=="richonline_route_static_effect_unsupported","paid_route_wrong_error");}
    check(f.debit_calls==0 && f.gold()==1000 && f.payment->reserve()==1000,"route_failure_after_debit");
}
void failed_diagnostics_preserve_payment_response(const std::filesystem::path& resources,const std::filesystem::path& root) {
    Flow f(resources,root/"broken-log.sqlite3",1000,1000,false,false,true);
    const auto response=f.send(paid(2));
    check(response.size()==1 && opcode(response[0])==0x4011 && response[0][8]==2 &&
        read_le(View(response[0]).subspan(24,4))==300,"logging_failure_lost_paid_response");
    check(f.gold()==700 && f.payment->reserve()==700 && f.debit_calls==1,"logging_failure_changed_payment");
    check(f.send(paid(2)).empty() && f.debit_calls==1,"logging_failure_repeated_charge");
    check(f.send(req(0x11,calendar+2,5)).size()==4 && f.session->state()==GameState::admitted,
        "logging_failure_interrupted_paid_movement");
}
void state_exclusion_and_database_failure(const std::filesystem::path& resources,const std::filesystem::path& root){
    Flow f(resources,root/"status.sqlite3",1000,1000);
    f.cards->commit_inventory(f.cards->prepare_add(1039));auto turtle=req(104,calendar+2,0,1);turtle.insert(turtle.end(),{0,0,0xcc});f.send(turtle);
    try{f.send(paid(2));throw std::runtime_error("turtle_paid_accepted");}
    catch(const CodecError& e){check(std::string(e.what())=="richonline_boss_paid_dice_status_forbidden","wrong_paid_status_error");}
    check(f.debit_calls==0 && f.gold()==1000,"forbidden_status_charged");
    Flow bad(resources,root/"db-error.sqlite3",1000,1000);
    bad.sql("CREATE TRIGGER fail_charge BEFORE INSERT ON audit WHEN NEW.source='native-game-charge' BEGIN SELECT RAISE(ABORT,'injected'); END");
    try{bad.send(paid(2));throw std::runtime_error("database_failure_hidden");}catch(const StorageError&){}
    check(bad.gold()==1000 && bad.payment->reserve()==1000 && bad.session->state()==GameState::closed,"database_failure_partly_committed");
    Flow replay(resources,root/"replay.sqlite3",1000,1000,false,true);
    try{replay.send(paid(2));throw std::runtime_error("restart_replay_fabricated_movement");}
    catch(const CodecError& e){check(std::string(e.what())=="richonline_boss_paid_dice_recovery_required","restart_replay_wrong_error");}
    check(replay.gold()==700 && replay.payment->reserve()==1000,"restart_replay_debited_again");
}
}
int main(int argc,char** argv){
    try{
        check(argc==2,"resource_root_required");const std::filesystem::path resources(argv[1]);
        const auto root=std::filesystem::temp_directory_path()/("payment-turns-"+std::to_string(GetCurrentProcessId())+"-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root);
        charge_moves_once(resources,root);refusal_keeps_turn(resources,root);
        invalid_route_precedes_debit(resources,root);state_exclusion_and_database_failure(resources,root);
        failed_diagnostics_preserve_payment_response(resources,root);
        random_dice_charge_and_retry(resources,root);random_dice_refusal_and_free_vehicle(resources,root);
        random_route_and_override_do_not_mischarge(resources,root);
        automatic_multi_dice_recovers_without_waiting_for_ui(resources,root);random_database_failure_and_replay_are_atomic(resources,root);
        std::filesystem::remove_all(root);
        std::cout<<"PASS encrypted paid-die turns, SQLite atomic charge, refusal, replay and route validation\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
