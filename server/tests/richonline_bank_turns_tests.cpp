#include "richonline_boss_turns.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_game_ledger.hpp"
#include "original_map.hpp"
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t gid=0x1234, calendar=0x4567;
void check(bool ok,const char* reason) { if (!ok) throw std::runtime_error(reason); }
void put(Bytes& data,std::size_t offset,std::uint32_t value) {
    for (std::size_t i=0;i<4;++i) data.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
RichonlineRoadTopology topology(bool repeated,bool boss_bank=false,bool junction=false) {
    const std::size_t count=junction ? 20 : 10;
    OriginalEmp emp{3,10,junction ? 2U : 1U,{}, {},Bytes(8+68*count,0xff),8,8+64*count,0,0};
    for (std::size_t i=0;i<10;++i) if (i<=(repeated?2U:4U) || i>=8) {
        emp.payload.at(emp.terrain_offset+64*i)=8;
        put(emp.payload,emp.tile_types_offset+4*i,0xffffffffU);
    }
    put(emp.payload,emp.tile_types_offset+4,9);
    if (!repeated) put(emp.payload,emp.tile_types_offset+12,9);
    if (boss_bank) put(emp.payload,emp.tile_types_offset+32,9);
    if (junction) emp.payload.at(emp.terrain_offset+64*11)=8;
    return richonline_road_topology(emp);
}
Bytes req(std::uint16_t op,std::uint16_t count,std::uint32_t value,std::size_t width=2) {
    Bytes b; append_le(b,op,2); append_le(b,count,2); append_le(b,value,width); return b;
}
Bytes decision(std::uint16_t count,std::uint16_t action,std::int32_t amount) {
    auto b=req(0x27,count,action); b.push_back(0xcc); b.push_back(0xdd);
    append_le(b,static_cast<std::uint32_t>(amount),4); return b;
}
std::uint16_t op(const Bytes& b) { return static_cast<std::uint16_t>(read_le(View(b).first(2))); }
std::vector<Bytes> decoded(const std::vector<Bytes>& frames) {
    std::vector<Bytes> result;
    for (const auto& bytes:frames) {
        const auto frame=decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
        if (frame.wire_type==1) continue;
        result.push_back(decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded));
    }
    return result;
}
struct Flow {
    RichonlineGameBank::Clock::time_point now{};
    std::shared_ptr<RichonlineGameLedger> ledger=std::make_shared<RichonlineGameLedger>(
        std::vector<RichonlineGameFunds>{{1000,200,150,{}},{5000,400,0,{}}});
    std::shared_ptr<RichonlineGameBank> bank=std::make_shared<RichonlineGameBank>(gid,
        RichonlineGameBankWirePolicy{0xa5,{0xb6,0xc7}},[this]{return now;});
    std::unique_ptr<GameSession> session;
    GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    unsigned random_calls=0;
    explicit Flow(unsigned die,bool repeated=false,bool boss_bank=false,bool junction=false) {
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {gid,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,0,3,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,9,1,{},0xc1}}},
            {gid,calendar,1,{{1000,200,150},{5000,400,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [this,die](std::size_t n) {
                check(n==6,"unexpected_route_fork");
                return random_calls++==1 ? static_cast<std::size_t>(die-1) : std::size_t{0};
            },[](const RichonlineLandingContext& ctx) {
                check(ctx.static_type==-1,"bank_was_delegated_to_generic_landing");
                Bytes stop; append_le(stop,0x4013,2); append_le(stop,gid,2);
                append_le(stop,static_cast<std::uint16_t>(ctx.position),2);
                return RichonlineLandingResult{{std::move(stop)},RichonlineLandingProgress::complete};
            },[](View)->RichonlineLandingResult { throw CodecError("unexpected_bank_generic_event"); }};
        rules.bank=bank; rules.ledger=ledger; rules.now=[this]{return now;};
        auto plan=make_richonline_boss_turns(startup,topology(repeated,boss_bank,junction),std::move(rules));
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& a)->std::optional<RichonlineStartupPlan> {
                return a==admission ? std::optional{plan} : std::nullopt;
            },[](std::size_t size){return Bytes(size,0x91);}));
        const auto init=decoded(session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(init.size()==1 && op(init[0])==0x4000,"bank_admission_failed");
        const auto opening=send({0,0}); check(opening.size()==4,"bank_opening_failed");
    }
    std::vector<Bytes> send(const Bytes& plain) {
        auto result=decoded(raw(plain));
        check(session->state()==GameState::admitted,"bank_flow_disconnected"); return result;
    }
    std::vector<Bytes> raw(const Bytes& plain) {
        return session->feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline}));
    }
    std::vector<Bytes> poll() {
        auto result=decoded(session->poll()); check(session->state()==GameState::admitted,"bank_timeout_disconnected"); return result;
    }
    void human_move() { send(req(0x11,calendar+1,8)); send(req(0x10,calendar+2,0,4)); }
};
void intermediate_transfer_and_resume() {
    Flow f(4); f.human_move();
    const auto opened=f.send(req(0x28,calendar+2,1));
    check(opened==std::vector<Bytes>{{0x18,0x40,0x34,0x12,1,0,1,0xa5}},"intermediate_admission_wrong");
    auto result=f.send(decision(calendar+2,0,300));
    check(result.size()==1 && op(result[0])==0x402a && result[0][6]==0xb6 &&
        read_le(View(result[0]).subspan(8,4))==300,"deposit_restarted_route_or_turn");
    check(f.ledger->snapshot(0).funds.cash==700 && f.ledger->snapshot(0).funds.deposit==500,
        "deposit_not_committed_to_shared_ledger");
    check(f.send(decision(calendar+2,0,300)).empty(),"late_bank_decision_doubled_transfer");
    f.send(req(0x28,calendar+2,3)); result=f.send(decision(calendar+2,1,100));
    check(result.size()==1 && op(result[0])==0x402a && f.ledger->snapshot(0).funds.cash==800 &&
        f.ledger->snapshot(0).funds.deposit==400,"second_bank_did_not_use_current_balance");
    result=f.send(req(0x11,calendar+2,4));
    check(result.size()==4 && op(result[0])==0x4013 && op(result[1])==0x4010,"bank_route_never_completed");
    check(f.send(decision(calendar+2,1,100)).empty(),"late_old_counter_bank_not_retired");
}
void timeout_and_repeated_position() {
    Flow f(6,true); f.human_move();
    for (unsigned visit=0;visit<3;++visit) {
        const auto opened=f.send(req(0x28,calendar+2,1)); check(opened.size()==1,"repeat_bank_not_opened");
        f.now+=std::chrono::milliseconds{7999}; check(f.poll().empty(),"bank_deadline_early");
        f.now+=std::chrono::milliseconds{1}; const auto closed=f.poll();
        check(closed.size()==1 && op(closed[0])==0x402a && closed[0][4]==2,"bank_timeout_did_not_resume_route");
        check(f.poll().empty() && f.send(decision(calendar+2,2,0)).empty(),"bank_timeout_repeated");
    }
    const auto done=f.send(req(0x11,calendar+2,2));
    check(done.size()==4 && op(done[1])==0x4010,"repeated_bank_cursor_lost_steps");
    check(f.ledger->snapshot(0).funds.cash==1000 && f.ledger->snapshot(0).funds.deposit==200,"timeouts_changed_funds");
}
void final_bank_and_synthetic_exit() {
    Flow f(1,false,true);
    const auto boss=f.send(req(0x11,calendar+1,8));
    check(boss.size()==5 && op(boss[0])==0x4013 && op(boss[1])==0x4018 && boss[1][6]==0 &&
        op(boss[2])==0x402a && boss[2][4]==2 && op(boss[3])==0x4010,"synthetic_final_bank_waited");
    f.send(req(0x10,calendar+2,0,4));
    const auto open=f.send(req(0x11,calendar+2,1));
    check(open.size()==2 && op(open[0])==0x4013 && op(open[1])==0x4018 && open[1][6]==0,"final_bank_open_order");
    f.now+=std::chrono::seconds{8}; const auto close=f.poll();
    check(close.size()==4 && op(close[0])==0x402a && op(close[1])==0x4010,"final_bank_timeout_stuck");
}
void invalid_checkpoint_disconnects() {
    const auto reject=[](Flow& f,const Bytes& packet,const char* expected) {
        try { f.raw(packet); throw std::runtime_error("invalid_bank_packet_accepted"); }
        catch (const CodecError& e) { check(std::string(e.what())==expected,"bank_wrong_rejection_reason"); }
        check(f.session->state()==GameState::closed,"invalid_bank_packet_did_not_close");
    };
    for (const auto& packet:{req(0x28,calendar+2,3),req(0x28,calendar+2,4),req(0x11,calendar+2,4)}) {
        Flow f(4); f.human_move();
        reject(f,packet,op(packet)==0x11 ? "richonline_boss_bank_checkpoint_skipped" : "richonline_boss_bank_checkpoint_mismatch");
        check(f.session->state()!=GameState::admitted,"out_of_order_or_skipped_checkpoint_accepted");
        check(f.ledger->snapshot(0).funds.cash==1000,"invalid_checkpoint_changed_funds");
    }
    Flow f(4); f.human_move(); f.send(req(0x28,calendar+2,1)); f.send(decision(calendar+2,2,0));
    reject(f,req(0x28,calendar+2,1),"richonline_boss_bank_checkpoint_mismatch");
    check(f.session->state()!=GameState::admitted,"duplicate_old_checkpoint_accepted");
}
void final_bank_preserves_junction() {
    Flow f(1,false,false,true); f.human_move();
    f.send(req(0x11,calendar+2,1));
    const auto closed=f.send(decision(calendar+2,0,100));
    check(closed.size()==1 && op(closed[0])==0x402a,"bank_skipped_final_junction");
    check(f.send(decision(calendar+2,0,100)).empty(),"same_counter_bank_replayed_in_junction");
    auto direction=req(0x34,calendar+2,0,1); direction.push_back(0xcc);
    const auto chosen=f.send(direction);
    check(chosen.size()==4 && op(chosen[0])==0x4035 && chosen[0][4]==0 && op(chosen[1])==0x4010,
        "bank_junction_choice_did_not_advance");
    f.send(req(0x11,calendar+3,9));
    const auto next=f.send(req(0x10,calendar+4,0,4));
    check(next.size()==1 && op(next[0])==0x4011,"bank_junction_next_roll_failed");
    const auto done=f.send(req(0x11,calendar+4,11));
    check(done.size()==4 && op(done[0])==0x4013,"bank_junction_heading_was_lost");
}
void bank_route_opt_in() {
    try { build_richonline_route(topology(false),{0,3,4,{}},{}); throw std::runtime_error("bank_route_unguarded"); }
    catch (const CodecError& e) { check(std::string(e.what())=="richonline_route_static_effect_unsupported","bank_guard_wrong"); }
    check(build_richonline_route(topology(false),{0,3,4,{},true,true},{}).landings==
        std::vector<std::int16_t>{1,2,3,4},"bank_route_opt_in_failed");
}
}
int main() {
    try {
        const auto run=[](const char* name,auto test) {
            try { test(); }
            catch (const std::exception& e) { throw std::runtime_error(std::string(name)+": "+e.what()); }
        };
        run("route_opt_in",bank_route_opt_in);
        run("intermediate_transfer",intermediate_transfer_and_resume);
        run("repeated_position",timeout_and_repeated_position);
        run("final_bank",final_bank_and_synthetic_exit);
        run("invalid_checkpoint",invalid_checkpoint_disconnects);
        run("final_junction",final_bank_preserves_junction);
        std::cout<<"PASS encrypted bank route checkpoints, shared transfers, timeout, replay and synthetic completion\n";
    } catch (const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
