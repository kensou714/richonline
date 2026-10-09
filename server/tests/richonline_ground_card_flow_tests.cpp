#include "richonline_boss_cards.hpp"
#include "richonline_ground_card.hpp"
#include "richonline_game_bank.hpp"
#include "original_map.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) {if(!value) throw std::runtime_error(reason);}
void put(Bytes& data,std::size_t offset,std::uint32_t value) {
    for(std::size_t i=0;i<4;++i) data.at(offset+i)=static_cast<std::uint8_t>(value>>(8*i));
}
RichonlineRoadTopology geometry(bool bank=false) {
    OriginalEmp emp{3,10,1,{},{},Bytes(688,0xff),8,648,0,0};
    for(std::size_t i=0;i<10;++i) if(i<=4 || i>=8) {
        emp.payload.at(emp.terrain_offset+64*i)=8;put(emp.payload,emp.tile_types_offset+4*i,0xffffffffU);
    }
    if(bank) put(emp.payload,emp.tile_types_offset+4,9);
    return richonline_road_topology(emp);
}
Bytes request(std::uint16_t opcode,std::uint16_t calendar,std::uint32_t argument,std::size_t width=2) {
    Bytes bytes;append_le(bytes,opcode,2);append_le(bytes,calendar,2);append_le(bytes,argument,width);return bytes;
}
std::uint16_t op(const Bytes& bytes) {return static_cast<std::uint16_t>(read_le(View(bytes).first(2)));}
struct Flow {
    std::shared_ptr<RichonlineBossCards> cards;
    std::shared_ptr<RichonlineGroundObjects> ground=std::make_shared<RichonlineGroundObjects>(
        std::vector<std::int16_t>{0,1,2,3,4,8,9});
    std::unique_ptr<GameSession> session;
    GameAdmission admission{0,3,25,{1,2,3,4,5,6,7,8},19,{}};
    explicit Flow(const std::filesystem::path& root,bool boss_banana=false,bool bank=false) {
        cards=std::make_shared<RichonlineBossCards>(std::make_shared<const RichonlineChanceResources>(
            RichonlineChanceResources::load(root)),0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
        RichonlineChanceInventory inventory{};inventory[0]={507,2};inventory[1]={502,2};cards->commit_inventory(inventory);
        if(boss_banana) ground->place(8,{30,255,255});
        RichonlineBossStartup startup{{3,25,{},{{1,25,0,true}}},
            {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
                {{25,0,3,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,9,1,{},0xc1}}},
            {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
        startup.room.description.record[36]=3;
        RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
            [](std::size_t){return std::size_t{0};},[](const RichonlineLandingContext& ctx) {
                return RichonlineLandingResult{{request(0x4013,0x1234,static_cast<std::uint16_t>(ctx.position))},
                    RichonlineLandingProgress::complete};
            },[](View)->RichonlineLandingResult{throw CodecError("unexpected_ground_card_event");}};
        rules.cards=cards;rules.ground=ground;
        if(bank) {
            rules.ledger=std::make_shared<RichonlineGameLedger>(
                std::vector<RichonlineGameFunds>{{20000,0,150,{}},{100000,0,0,{}}});
            rules.bank=std::make_shared<RichonlineGameBank>(0x1234,
                RichonlineGameBankWirePolicy{0xa5,{0xb6,0xc7}},[]{return RichonlineGameBank::Clock::time_point{};});
        }
        rules.ground_card_visible=[](std::uint8_t,std::int16_t source,std::int16_t target) {
            return target>=source-3 && target<=source+3;
        };
        auto plan=make_richonline_boss_turns(startup,geometry(bank),std::move(rules));
        session=std::make_unique<GameSession>(ClientVersion::richonline,make_richonline_game_callbacks(
            [this,plan=std::move(plan)](const GameAdmission& value)->std::optional<RichonlineStartupPlan> {
                return value==admission ? std::optional{plan}:std::nullopt;
            },[](std::size_t size){return Bytes(size,0x91);}));
        check(decode(session->feed(encode_frame(encode_game_admission(admission,ClientVersion::richonline),
            {Channel::game_c2s,{},ClientVersion::richonline}))).size()==1,"ground_card_admission_failed");
        const auto opened=send({0,0});check(opened.size()==4 && op(opened.back())==0x4011,"ground_card_opening_failed");
    }
    static std::vector<Bytes> decode(const std::vector<Bytes>& frames) {
        std::vector<Bytes> result;
        for(const auto& bytes:frames) {
            const auto frame=decode_frame(bytes,{Channel::game_s2c,{},ClientVersion::richonline});
            if(frame.wire_type!=1) result.push_back(decode_inner(decode_envelope(frame,ClientVersion::richonline).encoded));
        }
        return result;
    }
    std::vector<Bytes> send(const Bytes& plain) {
        auto result=decode(session->feed(encode_frame(richonline_board_frame(plain,{7,-2},Bytes(plain.size()+2,0x91)),
            {Channel::game_c2s,{},ClientVersion::richonline})));
        check(session->state()==GameState::admitted,"ground_card_flow_disconnected");return result;
    }
    void human_turn() {send(request(0x11,0x4568,8));}
};
void banana_placement_and_extended_route(const std::filesystem::path& root) {
    Flow f(root);f.human_turn();
    for(const std::uint8_t position:std::array<std::uint8_t,2>{1,2}) {
        const auto placed=f.send({165,0,0x69,0x45,0,0,position,0});
        check(placed==std::vector<Bytes>{{0xf5,0x40,0x34,0x12,0,0,position,0}},"banana_response_or_extra_turn_wrong");
    }
    check(f.cards->inventory()[0]==RichonlineChanceCardSlot{} && f.ground->snapshot().objects.size()==2,
        "banana_inventory_or_ground_not_committed");
    const auto move=f.send(request(0x10,0x4569,0,4));
    check(move.size()==1 && op(move[0])==0x4011 && move[0][6]==1 && move[0][8]==1 && move[0][7]==3,
        "banana_changed_base_die_or_missing_route_extension");
    check(f.ground->snapshot().objects.size()==2,"banana_consumed_before_movement_ack");
    const auto ended=f.send(request(0x11,0x4569,3));
    check(op(ended.front())==0x4013 && op(ended[1])==0x4010 && f.ground->snapshot().objects.empty(),
        "banana_did_not_extend_two_steps_and_continue");
}
void clear_card_preserves_roll_and_clears_all_dynamics(const std::filesystem::path& root) {
    Flow f(root);f.human_turn();
    f.ground->place(1,{30,255,255});f.ground->place(2,{12,1,3});f.ground->place(3,{2,255,255});
    for(const auto expected_count:{1,0}) {
        const auto cleared=f.send({160,0,0x69,0x45,1,0});
        check(cleared==std::vector<Bytes>{{0xf0,0x40,0x34,0x12,1,0}} && f.ground->snapshot().objects.empty(),
            "clear_ground_or_wire_wrong");
        check(f.cards->inventory()[1].count==expected_count,"clear_card_consumption_wrong");
    }
    f.send(request(0x10,0x4569,0,4));
    check(op(f.send(request(0x11,0x4569,1))[1])==0x4010,"clear_card_broke_next_move");
}
void synthetic_actor_consumes_banana_once_on_return(const std::filesystem::path& root) {
    Flow f(root,true);
    check(f.ground->snapshot().objects.size()==1,"boss_banana_consumed_before_ack");
    const auto result=f.send(request(0x11,0x4568,9));
    check(f.ground->snapshot().objects.empty(),"boss_banana_not_consumed");
    check(result.size()>=2 && op(result[1])==0x4010 && result[1][4]==0,"boss_banana_next_actor_wrong");
}
void extension_turns_endpoint_bank_into_intermediate_pause(const std::filesystem::path& root) {
    Flow f(root,false,true);f.human_turn();
    f.send({165,0,0x69,0x45,0,0,1,0});
    f.send(request(0x10,0x4569,0,4));
    const auto opened=f.send(request(0x28,0x4569,1));
    check(opened==std::vector<Bytes>{{0x18,0x40,0x34,0x12,1,0,1,0xa5}} && f.ground->snapshot().objects.empty(),
        "banana_bank_not_intermediate_or_consumption_delayed");
    auto close=request(0x27,0x4569,2);close.insert(close.end(),{0xcc,0xdd,0,0,0,0});
    const auto resumed=f.send(close);
    check(resumed.size()==1 && op(resumed[0])==0x402a,"banana_bank_restarted_route");
    const auto done=f.send(request(0x11,0x4569,2));
    check(op(done[0])==0x4013 && op(done[1])==0x4010,"banana_bank_could_not_finish_extended_route");
}
void malformed_ground_card_never_consumes_inventory(const std::filesystem::path& root) {
    for(const Bytes& packet:std::vector<Bytes>{{165,0,0x68,0x45,0,0,1,0},
        {165,0,0x69,0x45,0,1,1,0},{165,0,0x69,0x45,0,0,0,0},{160,0,0x69,0x45,0,0}}) {
        Flow f(root);f.human_turn();const auto hand=f.cards->inventory();const auto ground=f.ground->snapshot();
        bool rejected=false;try {rejected=f.send(packet)==std::vector<Bytes>{{0x0b,0x40,0x34,0x12,1}};} catch(const CodecError&) {rejected=true;}
        check(rejected && f.cards->inventory()==hand && f.ground->snapshot()==ground,
            "invalid_ground_card_committed_partial_authority");
    }
}
void roadblock_placement_stop_and_recovery(const std::filesystem::path& root) {
    Flow f(root);f.human_turn();auto hand=f.cards->inventory();hand[2]={1043,2};f.cards->commit_inventory(hand);
    check(f.send({108,0,0x69,0x45,2,0,1,0})==std::vector<Bytes>{{0xbc,0x40,0x34,0x12,2,0,1,0}},
        "roadblock_success_wire_wrong");
    check(f.ground->snapshot().objects.at(1)==RichonlineGroundObject{11,0,255},"roadblock_authority_wrong");
    const auto before=f.cards->inventory();
    check(f.send({108,0,0x69,0x45,2,0,1,0})==std::vector<Bytes>{{0x0b,0x40,0x34,0x12,1}} &&
        f.cards->inventory()==before,"roadblock_refusal_consumed_or_disconnected");
    f.send(request(0x10,0x4569,0,4));
    const auto done=f.send(request(0x11,0x4569,1));
    check(op(done[0])==0x4013 && op(done[1])==0x4010 && f.ground->snapshot().objects.empty(),
        "roadblock_not_removed_or_next_turn_missing");
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=2) return 2;const auto root=std::filesystem::path(argv[1]);
        banana_placement_and_extended_route(root);clear_card_preserves_roll_and_clears_all_dynamics(root);
        synthetic_actor_consumes_banana_once_on_return(root);
        extension_turns_endpoint_bank_into_intermediate_pause(root);malformed_ground_card_never_consumes_inventory(root);
        roadblock_placement_stop_and_recovery(root);
        std::cout<<"PASS encrypted NEW165/160 shared ground and human/BOSS banana movement\n";
    } catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
