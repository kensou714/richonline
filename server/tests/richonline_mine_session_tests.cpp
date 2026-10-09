#include "richonline_boss_session.hpp"
#include "richonline_levels.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t game=0x1234,calendar=0x4567;
void check(bool ok,const char* reason) { if(!ok) throw std::runtime_error(reason); }
std::uint32_t opcode(const Bytes& packet) { return read_le(View(packet).first(2)); }
std::size_t count(const std::vector<Bytes>& packets,std::uint32_t code) {
    return static_cast<std::size_t>(std::count_if(packets.begin(),packets.end(),
        [code](const auto& packet){return opcode(packet)==code;}));
}
Bytes request(std::uint16_t code,std::uint16_t counter,std::uint32_t value,std::size_t width=2) {
    Bytes result;append_le(result,code,2);append_le(result,counter,2);append_le(result,value,width);return result;
}
std::vector<Bytes> decode(const std::vector<Bytes>& frames) {
    std::vector<Bytes> result;
    for(const auto& wire:frames) {
        const auto frame=decode_frame(wire,{Channel::game_s2c,{},ClientVersion::richonline});
        if(frame.wire_type==1) {check(frame.payload.empty(),"mine_admission_ack_payload");continue;}
        const auto envelope=decode_envelope(frame,ClientVersion::richonline);
        check(envelope.inner_type==7 && envelope.mode==-2,"mine_session_envelope_changed");
        result.push_back(decode_inner(envelope.encoded));
    }
    return result;
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");const std::filesystem::path root(argv[1]);
        const auto& package=legacy_richonline_map_package();const auto stage=package.load_stage(root,0);
        const auto topology=load_richonline_road_topology(root/"Map"/stage.map_name);
        constexpr std::int16_t target_position=182;
        const auto& target=topology.cell(target_position);
        check(target.walkable && target.property_ref==-1 && target.static_type==5 &&
            !topology.portal_destination(target_position),"real_mine_ticket_endpoint_changed");
        std::optional<std::pair<std::int16_t,std::uint8_t>> approach;
        for(std::uint8_t direction=0;direction<4 && !approach;++direction) if(target.neighbors[direction]) {
            const auto adjacent=*target.neighbors[direction];
            const auto heading=static_cast<std::uint8_t>((direction+2U)%4U);
            const auto route=build_richonline_route(topology,{adjacent,heading,1,{}},
                [](std::size_t){return std::size_t{0};});
            if(route.landings==std::vector<std::int16_t>{target_position})
                approach=std::pair{adjacent,heading};
        }
        check(approach.has_value(),"real_mine_ticket_approach_changed");
        const auto path=std::filesystem::temp_directory_path()/std::filesystem::path("mine-session-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+".sqlite3");
        Storage storage(path,ClientProfile::richonline);
        const auto actor=storage.dispatch("accounts.create",{{"username","mine-session"},{"password","fixture"}})
            .at("account").at("role_id").get<std::uint32_t>();
        check(actor<=32767,"actor_out_of_range");
        RichonlineBossStartup startup{{3,actor,{},{{1,actor,0,true}}},
            {game,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{static_cast<std::int16_t>(actor),approach->first,approach->second,
                    {5,5,5,5,5,5,5,5,5,5},0xb1},{-1,236,1,{},0xc1}}},
            {game,calendar,1,{{100000,0,150},{100000,0,0}}},{7,-2},std::array<std::uint32_t,32>{}};
        startup.room.description.record[36]=3;
        auto& extension=startup.room.description.extension;extension.resize(88);
        std::copy(stage.map_name.begin(),stage.map_name.end(),extension.begin());
        std::copy(stage.signature.begin(),stage.signature.end(),extension.begin()+32);
        const auto compatibility=richonline_boss_result_byte18_compatibility(
            "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77",3);
        const auto settlement=richonline_boss_settlement_policy(stage,load_richonline_level_thresholds(root),
            {"Fixture explicit resource victory policy; loss/draw award nothing",true,0,0,{0,0,0},{0,0,0}});
        auto terminal=std::make_shared<RichonlineTerminalCoordinator>(storage,RichonlineTerminalContext{
            "mine-session",actor,game,3,{"fixture-settlement","fixture-match",stage.map_name,GameOutcome::loss,
                stage.pawn_gold,{},settlement},{3,0,{1},{}},
            {"Fixture simultaneous loss policy",RichonlineSimultaneousDefeat::human_loss,1,2,2,compatibility.value,false},
            compatibility.evidence});
        auto attack_draw=std::make_shared<std::size_t>(0);
        auto admitted=std::make_shared<std::size_t>(0);
        auto seen_funds=std::make_shared<std::vector<RichonlineGameFunds>>();
        RichonlineBossSessionPolicy policy{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [attack_draw](std::size_t bound) {
                if(bound==100) {
                    const auto draw=(*attack_draw)++;
                    return draw==0 || draw==4 ? std::size_t{80}:std::size_t{0};
                }
                return std::size_t{0};
            },RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}}};
        policy.terminal=terminal;
        policy.result_display=RichonlineResultDisplayPolicy{std::chrono::milliseconds{6000},
            [] {return std::chrono::steady_clock::time_point{};}};
        policy.combat=RichonlineCombatWorldPolicy{
            {"server_manhattan_tile_radius",64,RichonlineProjectileCandidates::all_map_tiles},{13},
            [admitted,seen_funds](std::int16_t position,const RichonlineCombatSessionView& state) {
                const auto after_step=state.actors[0] && state.actors[0]->position==target_position;
                if(position!=(after_step?115:target_position))return false;
                if(state.actors[0])seen_funds->push_back(state.actors[0]->funds.funds);
                ++*admitted;return true;
            },{},{},{}};
        auto plan=make_richonline_boss_session(root,startup,package,policy,
            std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root)),{});
        terminal->prepare_start();
        const GameAdmission admission{0,3,actor,{1,2,3,4,5,6,7,8},19,{}};
        GameSession session(ClientVersion::richonline,make_richonline_game_callbacks(
            [plan=std::move(plan),admission](const GameAdmission& value)->std::optional<RichonlineStartupPlan> {
                return value==admission ? std::optional{plan}:std::nullopt;
            },[](std::size_t size){return Bytes(size,0x91);}));
        const auto joined=decode(session.feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(joined.size()==1 && opcode(joined[0])==0x4000,"mine_session_admission_failed");
        auto send=[&session](const Bytes& plain) {
            return decode(session.feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
                {Channel::game_c2s,{},ClientVersion::richonline})));
        };
        const auto opening=send({0,0});
        check(*admitted>0 && count(opening,0x40bd)==1 && count(opening,0x4011)==1,
            "real_preflight_did_not_admit_ticket_mine");
        const auto mine=std::find_if(opening.begin(),opening.end(),[](const auto& packet){return opcode(packet)==0x40bd;});
        check(mine!=opening.end() && read_le(View(*mine).subspan(6,2))==target_position,
            "boss_mine_wrong_real_endpoint");
        const auto human=send(request(0x11,calendar+1,235));
        check(count(human,0x4010)==1 && std::find_if(human.begin(),human.end(),[](const auto& packet){
            return opcode(packet)==0x4010 && packet[4]==0;})!=human.end(),"boss_did_not_finish_before_human");
        const auto movement=send(request(0x10,calendar+2,0,4));
        check(count(movement,0x4011)==1,"human_mine_approach_did_not_move");
        const auto stopped=send(request(0x11,calendar+2,static_cast<std::uint32_t>(target_position)));
        check(count(stopped,0x4013)==1 && count(stopped,0x4017)==0 && count(stopped,0x4029)==0 &&
            count(stopped,0x4096)==0 && count(stopped,0x4010)==1 && count(stopped,0x4011)==1,
            "stepped_mine_ticket_landing_did_not_close_once");
        const auto stop=std::find_if(stopped.begin(),stopped.end(),[](const auto& packet){return opcode(packet)==0x4013;});
        check(*stop==Bytes({0x13,0x40,0x34,0x12,182,0}),"stop_did_not_name_ticket_reward_endpoint");
        // NEW applies the type5 +80 ticket reward locally from this one4013.
        // No additional reward ACK is expected; both following actors must progress.
        const auto following=send(request(0x11,calendar+3,234));
        check(std::ranges::any_of(*seen_funds,[](const auto& funds) {
            return funds.tickets==230 && funds.cash==97000;
        }),"stepped_mine_did_not_debit_3000_cash_and_award_80_tickets");
        check(count(following,0x4010)==1 && count(send(request(0x10,calendar+4,0,4)),0x4011)==1 &&
            session.state()==GameState::admitted && terminal->phase()==RichonlineTerminalPhase::playing,
            "mine_ticket_endpoint_stalled_following_turn");
        std::cout<<"PASS real BS_1_1 encrypted session: legal type5 mine182, single4013, +80 tickets, mine damage and next turns\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
