#include "richonline_boss_shop.hpp"
#include "richonline_boss_landing.hpp"
#include "game_session.hpp"
#include <algorithm>
#include <iostream>

namespace {
using namespace richnet;
constexpr std::uint16_t game_id=0x1234, initial_counter=0x4567;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
Bytes request(std::uint16_t opcode,std::uint16_t counter,std::uint32_t value,std::size_t width=2) {
    Bytes bytes; append_le(bytes,opcode,2); append_le(bytes,counter,2); append_le(bytes,value,width); return bytes;
}
Bytes choice(std::uint16_t opcode,std::int8_t value) {
    auto result=request(opcode,initial_counter+2,static_cast<std::uint8_t>(value),1);
    result.push_back(0xcc); return result;
}
std::vector<Bytes> decode(const std::vector<Bytes>& frames) {
    std::vector<Bytes> result;
    for (const auto& bytes:frames) {
        const auto frame=decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
        if (frame.wire_type==1) { check(frame.payload.empty(),"admission_ack_not_empty"); continue; }
        check(frame.wire_type==299,"response_envelope_missing");
        const auto envelope=decode_envelope(frame,ClientVersion::richonline);
        check(envelope.inner_type==7 && envelope.mode==-2,"response_envelope_policy_changed");
        result.push_back(decode_inner(envelope.encoded));
    }
    return result;
}
struct Flow {
    RichonlineRoadTopology topology;
    RichonlineBossShop::Clock::time_point now{};
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineBossLandingState> balances;
    std::shared_ptr<RichonlineBossShop> shop;
    std::unique_ptr<GameSession> session;
    const GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    std::uint8_t incoming=0;
    explicit Flow(const std::filesystem::path& root,std::int16_t destination,bool boss=false)
        :topology(load_richonline_road_topology(root/"Map/BS_1_1.emp")),
        cards(std::make_shared<RichonlineBossCards>(std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root)),
            game_id,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}})),
        balances(std::make_shared<RichonlineBossLandingState>(game_id,std::array<std::uint32_t,2>{150,0})),
        shop(std::make_shared<RichonlineBossShop>(root,*cards,game_id,[this] { return now; })) {
        const auto& cell=topology.cell(destination);
        check(cell.static_type==10 && cell.property_ref==-1 &&
            std::count_if(cell.neighbors.begin(),cell.neighbors.end(),[](auto edge) { return edge.has_value(); })==3,
            "real_shop_junction_fixture_changed");
        check(cell.neighbors[2].has_value(),"fixture_incoming_road_missing");
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {game_id,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,115,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,236,1,{},0xc1}}},
            {game_id,initial_counter,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        auto& actor=startup.init.participants[boss ? 1U : 0U];
        actor.position=*cell.neighbors[2]; actor.direction=incoming;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [](std::size_t) { return std::size_t{0}; },
            [this](const RichonlineLandingContext& ctx) {
                if (auto result=shop->land(ctx,balances->points()[0])) return *result;
                return balances->land(ctx);
            },[this](View plain) {
                const auto before=balances->points()[0]; auto result=shop->handle(plain);
                balances->commit_points(0,before,shop->points()); return result;
            }};
        rules.cards=cards; rules.now=[this] { return now; };
        rules.poll=[this] {
            const auto before=balances->points()[0]; auto result=shop->poll();
            if (result) balances->commit_points(0,before,shop->points());
            return result;
        };
        auto plan=make_richonline_boss_turns(startup,topology,std::move(rules));
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& ticket)->std::optional<RichonlineStartupPlan> {
                return ticket==admission ? std::optional{plan} : std::nullopt;
            },[](std::size_t size) { return Bytes(size,0x91); }));
        const auto init=decode(session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(init.size()==1 && read_le(View(init[0]).first(2))==0x4000,"pipeline_admission_failed");
        const auto opening=send(Bytes{0,0});
        check(opening.size()==4 && opening[1][4]==1,"boss_first_opening_missing");
    }
    std::vector<Bytes> send(const Bytes& plain) {
        auto result=decode(session->feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(session->state()==GameState::admitted,"valid_junction_flow_disconnected"); return result;
    }
    std::vector<Bytes> poll() { auto result=decode(session->poll()); check(session->state()==GameState::admitted,"junction_timer_disconnected"); return result; }
    void enter_human_shop(std::int16_t position) {
        send(request(0x11,initial_counter+1,235));
        send(request(0x10,initial_counter+2,0,4));
        const auto opened=send(request(0x11,initial_counter+2,static_cast<std::uint16_t>(position)));
        check(opened.size()==2 && read_le(View(opened[0]).first(2))==0x4013 &&
            read_le(View(opened[1]).first(2))==0x4030 && shop->active(),"junction_shop_not_opened");
    }
};
void human_shop_direction_flow(const std::filesystem::path& root,std::int16_t position,bool shop_timeout,bool direction_timeout) {
    Flow flow(root,position); flow.enter_human_shop(position);
    if (shop_timeout) flow.now+=std::chrono::seconds{10};
    const auto closed=shop_timeout ? flow.poll() : flow.send(choice(0x30,-1));
    check(closed==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0xff}} && !flow.shop->active(),
        "shop_close_advanced_actor_before_final_choice");
    check(flow.send(choice(0x30,-1)).empty(),"late_shop_exit_repeated_during_direction_wait");
    check(flow.send(choice(0x31,0)).empty(),"late_shop_sale_repeated_during_direction_wait");
    check(flow.poll().empty(),"direction_wait_advanced_immediately");
    const auto& cell=flow.topology.cell(position);
    std::uint8_t selected=0;
    for (std::uint8_t candidate=1;candidate<4;++candidate)
        if (candidate!=2 && cell.neighbors[candidate]) { selected=candidate; break; }
    check(selected!=flow.incoming,"fixture_lacks_alternate_direction");
    std::vector<Bytes> resumed;
    if (direction_timeout) {
        flow.now+=std::chrono::milliseconds{5999}; check(flow.poll().empty(),"direction_deadline_early");
        flow.now+=std::chrono::milliseconds{1}; resumed=flow.poll();
    } else resumed=flow.send(choice(0x34,static_cast<std::int8_t>(selected)));
    const auto response_direction=direction_timeout ? std::uint8_t{255} : selected;
    check(resumed.size()==4 && resumed[0]==Bytes({0x35,0x40,0x34,0x12,response_direction}) &&
        read_le(View(resumed[1]).first(2))==0x4010 && resumed[1][4]==1,
        "direction_confirmation_must_precede_next_actor");
    check(flow.poll().empty(),"direction_resolution_repeated");
    check(flow.send(choice(0x34,static_cast<std::int8_t>(selected))).empty(),"late_direction_not_retired");
    check(flow.send(choice(0x30,-1)).empty(),"late_shop_not_retired_after_direction");
    const auto boss_stop=flow.send(request(0x11,initial_counter+3,234));
    check(boss_stop.size()==3 && boss_stop[1][4]==0,"next_human_turn_missing");
    const auto movement=flow.send(request(0x10,initial_counter+4,0,4));
    const auto expected=build_richonline_route(flow.topology,{position,direction_timeout ? flow.incoming : selected,1,{}},
        [](std::size_t) { return std::size_t{0}; });
    check(movement.size()==1 && read_le(View(movement[0]).subspan(4,2))==static_cast<std::uint16_t>(position) &&
        (movement[0][11]&3U)==expected.directions.front(),"next_roll_ignored_final_direction");
    check(flow.balances->points()[0]==150,"shop_exit_or_direction_changed_points");
}
void boss_shop_does_not_wait_for_direction(const std::filesystem::path& root,std::int16_t position) {
    Flow flow(root,position,true);
    const auto result=flow.send(request(0x11,initial_counter+1,static_cast<std::uint16_t>(position)));
    check(result.size()==4 && read_le(View(result[0]).first(2))==0x4013 &&
        result[1]==Bytes({0x31,0x40,0x34,0x12,0xff}) && result[2][4]==0,
        "boss_junction_shop_waited_for_human_choice");
    flow.now+=std::chrono::seconds{20}; check(flow.poll().empty(),"boss_created_direction_timeout");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required"); const std::filesystem::path root(argv[1]);
        for (const auto position:{std::int16_t{178},std::int16_t{189}}) {
            human_shop_direction_flow(root,position,false,false);
            human_shop_direction_flow(root,position,true,false);
            human_shop_direction_flow(root,position,true,true);
            boss_shop_does_not_wait_for_direction(root,position);
        }
        std::cout<<"PASS encrypted GameSession real shop junction choice, deadlines and retired actions\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
