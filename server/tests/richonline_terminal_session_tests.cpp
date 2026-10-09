#include "richonline_boss_session.hpp"
#include "richonline_levels.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if(!value)throw std::runtime_error(reason); }
std::uint32_t opcode(const Bytes& packet) {return read_le(View(packet).first(2));}
std::size_t count(const std::vector<Bytes>& packets,std::uint32_t code) {
    return static_cast<std::size_t>(std::count_if(packets.begin(),packets.end(),[&](const auto& packet){return opcode(packet)==code;}));
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");const std::filesystem::path root(argv[1]);
        const auto& package=legacy_richonline_map_package();const auto stage=package.load_stage(root,0);
        const auto path=std::filesystem::temp_directory_path()/std::filesystem::path("terminal-session-"+
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+".sqlite3");
        Storage storage(path,ClientProfile::richonline);
        const auto actor=storage.dispatch("accounts.create",{{"username","terminal-session"},{"password","fixture"}})
            .at("account").at("role_id").get<std::uint32_t>();
        check(actor<=32767,"actor_out_of_range");
        RichonlineBossStartup startup{{3,actor,{},{{1,actor,0,true}}},
            {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{static_cast<std::int16_t>(actor),122,1,{5,5,5,5,5,5,5,5,5,5},0xb1},{-1,236,1,{},0xc1}}},
            {0x1234,0x4567,1,{{1,0,150},{100000,0,0}}},{7,-2},std::array<std::uint32_t,32>{}};
        startup.room.description.record[36]=3;
        auto& extension=startup.room.description.extension;extension.resize(88);
        std::copy(stage.map_name.begin(),stage.map_name.end(),extension.begin());
        std::copy(stage.signature.begin(),stage.signature.end(),extension.begin()+32);
        const auto compatibility=richonline_boss_result_byte18_compatibility(
            "cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77",3);
        const auto settlement=richonline_boss_settlement_policy(stage,load_richonline_level_thresholds(root),
            {"Fixture explicit resource victory policy; loss/draw award nothing",true,0,0,{0,0,0},{0,0,0}});
        auto terminal=std::make_shared<RichonlineTerminalCoordinator>(storage,RichonlineTerminalContext{
            "terminal-session",actor,0x1234,3,{"fixture-settlement","fixture-match",stage.map_name,GameOutcome::loss,
                stage.pawn_gold,{},settlement},{3,0,{1},{}},
            {"Fixture simultaneous loss policy",RichonlineSimultaneousDefeat::human_loss,1,2,2,compatibility.value,false},
            compatibility.evidence});
        auto now=std::chrono::steady_clock::time_point{};
        auto attack_draw=std::make_shared<std::size_t>(0);
        const auto map_cells=static_cast<std::size_t>(stage.width)*stage.height;
        RichonlineBossSessionPolicy policy{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [attack_draw,map_cells](std::size_t bound) {
                if(bound==100)return (*attack_draw)++==0 ? std::size_t{90}:std::size_t{0};
                if(bound==map_cells)return std::size_t{122};
                return std::size_t{0};
            },RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}}};
        policy.terminal=terminal;
        policy.result_display=RichonlineResultDisplayPolicy{std::chrono::milliseconds{6000},[&]{return now;}};
        policy.combat=RichonlineCombatWorldPolicy{{"server_manhattan_tile_radius",64,RichonlineProjectileCandidates::all_map_tiles},
            {13},[](std::int16_t,const RichonlineCombatSessionView&){return true;},{},{},{}};
        auto plan=make_richonline_boss_session(root,startup,package,policy,
            std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root)),{});
        check(!plan.terminal_pending() && !plan.game_finished(),"terminal_active_before_board_start");
        terminal->prepare_start();const auto before=storage.game_account_for_role(actor).gold;
        const auto packets=plan.map_ready();
        check(count(packets,0x40bf)==1 && count(packets,0x401b)==1 && count(packets,0x400f)==1 &&
            count(packets,0x420f)==0 && count(packets,0x4011)==0,
            "live_combat_bankruptcy_did_not_close_into_result");
        check(terminal->phase()==RichonlineTerminalPhase::delivering && plan.terminal_pending(),"result_not_committed");
        now+=std::chrono::hours{1};check(!plan.game_finished(),"delay_started_before_transport_confirmations");
        plan.sent(Bytes{0x10,0x40,0x34,0x12});check(!plan.game_finished(),"unrelated_frame_advanced_result");
        for(const auto& packet:packets)plan.sent(packet);
        check(!plan.game_finished(),"results_did_not_get_display_time");
        plan.disconnected();
        check(terminal->phase()==RichonlineTerminalPhase::delivering && plan.terminal_pending(),
            "game_transport_close_lost_lobby_result_binding");
        now+=std::chrono::milliseconds{5999};check(!plan.game_finished(),"premature_lobby_return");
        now+=std::chrono::milliseconds{1};check(plan.game_finished(),"lobby_return_missing_after_delay");
        plan.lobby_sent({58,Bytes{0xff}});check(plan.game_finished(),"wrong_lobby_frame_confirmed_result");
        plan.lobby_sent(richonline_lobby_game_finished(3));
        check(!plan.game_finished() && terminal->phase()==RichonlineTerminalPhase::finished &&
            storage.pending_game_settlements("terminal-session",actor).empty(),"lobby_result_not_checkpointed");
        plan.disconnected();check(storage.game_account_for_role(actor).gold==before,"result_cleanup_changed_account_again");
        std::cout<<"PASS real combat/session/SQLite result flow, whole-send checkpoints, display delay and lobby return\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
