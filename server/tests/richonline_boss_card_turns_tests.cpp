#include "richonline_boss_cards.hpp"
#include "richonline_boss_landing.hpp"
#include "richonline_boss_property.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_boss_shop.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason) { if (!value) throw std::runtime_error(reason); }
RichonlineBossStartup startup() {
    RichonlineBossStartup value{{3,25,{},{{1,25,0,true}}},
        {0x1234,{0,0,0,0,0,0,0xf0,0x3f},2026,10,9,5,0,0xa1,
            {{25,115,1,{7,7,7,7,7,7,7,7,7,7},0xb1},{-1,236,1,{},0xc1}}},
        {0x1234,0x4567,1,{{20000,0,150},{100000,0,0}}},{7,-2}};
    value.room.description.record[36]=3;
    return value;
}
Bytes request(std::uint16_t opcode,std::uint16_t counter,std::uint32_t value,std::size_t width=2) {
    Bytes bytes; append_le(bytes,opcode,2); append_le(bytes,counter,2); append_le(bytes,value,width); return bytes;
}
Bytes selected(std::uint8_t slot,std::uint8_t die) {
    return {103,0,0x6b,0x45,slot,0,die,0xa5,0,0,0,0};
}
void awarded_card_drives_move_without_second_roll(const std::filesystem::path& root) {
    auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
    std::vector<std::string> logs;
    RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [](std::size_t) { return std::size_t{0}; },
        [](const RichonlineLandingContext& ctx) { return resolve_richonline_empty_boss_landing(0x1234,ctx); },
        [](View)->RichonlineLandingResult { throw CodecError("unexpected_landing_event"); }};
    rules.cards=cards; rules.log=[&](const std::string& line) { logs.push_back(line); };
    auto plan=make_richonline_boss_turns(startup(),load_richonline_road_topology(root/"Map/BS_1_1.emp"),std::move(rules));
    plan.map_ready();
    plan.action({},request(0x11,0x4568,235));
    plan.action({},request(0x10,0x4569,0,4));
    const auto reward=plan.action({},request(0x11,0x4569,114));
    check(reward.size()==5 && reward[0]==Bytes({0x13,0x40,0x34,0x12,114,0}) &&
        reward[1]==Bytes({0x96,0x40,0x34,0x12,17,0,0xa5,0x5a,0x0e,0x04,0,0}) &&
        reward[2][0]==0x10 && reward[2][4]==1,"reward_before_boss_turn");
    check(cards->inventory()[0]==RichonlineChanceCardSlot{1038,1},"reward_inventory_missing");
    plan.action({},request(0x11,0x456a,234));
    const auto rejected=plan.action({},selected(1,6));
    check(rejected==std::vector<Bytes>{{0x0b,0x40,0x34,0x12,1}} && !logs.empty(),"empty_slot_does_not_recover_controls");
    check(cards->inventory()[0].card_id==1038,"rejected_use_consumes_another_slot");
    const auto paid=plan.action({},Bytes{22,0,0x6b,0x45,5,0xa5});
    check(paid==rejected && cards->inventory()[0].card_id==1038,"unsupported_paid_roll_changed_inventory");
    const auto moved=plan.action({},selected(0,3));
    check(moved.size()==2 && moved[0]==Bytes({0xb7,0x40,0x34,0x12,0,0}) &&
        moved[1][0]==0x11 && moved[1][4]==114 && moved[1][7]==3 && moved[1][8]==3 &&
        read_le(View(moved[1]).subspan(24,4))==0,"selected_die_does_not_immediately_move");
    check(cards->inventory()[0]==RichonlineChanceCardSlot{},"card_not_consumed_once");
    try { plan.action({},selected(0,3)); throw std::runtime_error("duplicate_use_accepted"); }
    catch (const CodecError& error) { check(std::string(error.what())=="richonline_boss_card_out_of_phase","wrong_duplicate_rejection"); }
    plan.disconnected();
}
void discarded_stack_cannot_be_used_and_does_not_end_turn(const std::filesystem::path& root) {
    auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
    RichonlineChanceInventory inventory{}; inventory[0]={1038,2}; inventory[1]={1044,1};
    cards->commit_inventory(inventory);
    RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [](std::size_t) { return std::size_t{0}; },
        [](const RichonlineLandingContext& ctx) { return resolve_richonline_empty_boss_landing(0x1234,ctx); },
        [](View)->RichonlineLandingResult { throw CodecError("unexpected_landing_event"); }};
    rules.cards=cards;
    auto plan=make_richonline_boss_turns(startup(),load_richonline_road_topology(root/"Map/BS_1_1.emp"),std::move(rules));
    plan.map_ready(); plan.action({},request(0x11,0x4568,235));
    const auto dropped=plan.action({},Bytes{50,0,0x69,0x45,0,0xcc});
    check(dropped==std::vector<Bytes>{{0x33,0x40,0x34,0x12,0,0}} &&
        cards->inventory()[0]==RichonlineChanceCardSlot{} && cards->inventory()[1]==inventory[1],"discard_did_not_remove_exact_stack");
    check(plan.action({},selected(0,4))==std::vector<Bytes>{{0x0b,0x40,0x34,0x12,1}},"discarded_card_remained_usable");
    const auto move=plan.action({},request(0x10,0x4569,0,4));
    check(move.size()==1 && move[0][0]==0x11,"discard_ended_turn_instead_of_preserving_roll");
}
void purchase_timeout_resumes_turn_and_retires_old_click(const std::filesystem::path& root,
    std::int16_t start=233,std::int16_t destination=232,std::uint8_t direction=1) {
    auto initial=startup(); initial.init.participants[0].position=start;
    initial.init.participants[0].direction=direction;
    auto now=RichonlineBossProperty::Clock::time_point{};
    auto property=std::make_shared<RichonlineBossProperty>(root,0x1234,std::array<std::uint32_t,2>{20000,100000},
        load_richonline_boss_stage(root,"BS_1_1.emp"));
    property->enable_human_decisions(std::chrono::seconds{10},[&] { return now; });
    RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [](std::size_t) { return std::size_t{0}; },
        [property](const RichonlineLandingContext& ctx) { if(auto r=property->land(ctx)) return *r; return resolve_richonline_empty_boss_landing(0x1234,ctx); },
        [property](View plain) { return property->decide(plain); }};
    rules.poll=[property] { return property->poll(); };
    auto plan=make_richonline_boss_turns(initial,load_richonline_road_topology(root/"Map/BS_1_1.emp"),std::move(rules));
    plan.map_ready(); plan.action({},request(0x11,0x4568,235));
    plan.action({},request(0x10,0x4569,0,4));
    const auto pending=plan.action({},request(0x11,0x4569,static_cast<std::uint16_t>(destination)));
    check(pending==std::vector<Bytes>{{0x13,0x40,0x34,0x12,static_cast<std::uint8_t>(destination),0}},"purchase_did_not_wait_for_decision");
    check(static_cast<bool>(plan.poll),"property_turn_poll_missing");
    check(plan.poll().empty(),"purchase_advanced_before_deadline");
    now+=std::chrono::seconds{10}; const auto expired=plan.poll();
    check(expired.size()==4 && expired[0]==Bytes({0x20,0x40,0x34,0x12,0}) && expired[1][0]==0x10 && expired[1][4]==1,"timeout_did_not_resume_boss_turn");
    check(plan.poll().empty() && property->cash()[0]==20000,"timeout_repeated_or_charged");
    const Bytes late{0x20,0,0x69,0x45,0,0,0,0,1,0xaa,0xbb,0xcc};
    check(plan.retired_action && plan.retired_action(late),"late_purchase_not_retired");
    auto unrelated=late; unrelated[2]++; check(!plan.retired_action(unrelated),"unrelated_counter_retired");
    plan.disconnected(); check(plan.poll().empty() && !plan.retired_action(late),"closed_game_still_polls");
}
void shop_closes_without_waiting_for_client_timeout_ack(const std::filesystem::path& root,bool expire) {
    auto resources=std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(root));
    auto cards=std::make_shared<RichonlineBossCards>(resources,0x1234,RichonlineBossCardPolicy{"BS_1_1.emp",17,1038,{0xa5,0x5a}});
    auto balances=std::make_shared<RichonlineBossLandingState>(0x1234,std::array<std::uint32_t,2>{150,0});
    auto now=RichonlineBossShop::Clock::time_point{};
    auto shop=std::make_shared<RichonlineBossShop>(root,*cards,0x1234,[&] { return now; });
    RichonlineBossTurnRules rules{0xa2,{-7,9},{{0xa3,0xb3,0xc3,0xd3},0,{}},
        [](std::size_t) { return std::size_t{0}; },
        [shop,balances](const RichonlineLandingContext& ctx) {
            if (auto result=shop->land(ctx,balances->points()[0])) return *result;
            return balances->land(ctx);
        },[shop,balances](View plain) {
            const auto before=balances->points()[0]; auto result=shop->handle(plain);
            balances->commit_points(0,before,shop->points()); return result;
        }};
    rules.cards=cards;
    rules.poll=[shop,balances] {
        const auto before=balances->points()[0]; auto result=shop->poll();
        if (result) balances->commit_points(0,before,shop->points());
        return result;
    };
    auto initial=startup(); initial.init.participants[0].position=116; initial.init.participants[0].direction=3;
    auto plan=make_richonline_boss_turns(initial,load_richonline_road_topology(root/"Map/BS_1_1.emp"),std::move(rules));
    plan.map_ready(); plan.action({},request(0x11,0x4568,235));
    plan.action({},request(0x10,0x4569,0,4));
    const auto opened=plan.action({},request(0x11,0x4569,117));
    check(opened.size()==2 && opened[1][0]==0x30 && shop->active(),"human_shop_did_not_open");
    const auto bought=plan.action({},Bytes{0x30,0,0x69,0x45,0,0xcc});
    check(bought==std::vector<Bytes>{{0x31,0x40,0x34,0x12,0}} && cards->inventory()[0].card_id==1038 &&
        balances->points()[0]==150-shop->price(),"shop_purchase_not_committed");
    const auto sold=plan.action({},Bytes{0x31,0,0x69,0x45,0,0xcc});
    check(sold==std::vector<Bytes>{{0x32,0x40,0x34,0x12,0}} && cards->inventory()[0].card_id==-1 &&
        balances->points()[0]==150-shop->price()+shop->price()/2,"shop_sale_not_committed");
    const Bytes exit{0x30,0,0x69,0x45,0xff,0xcc};
    if (expire) now+=std::chrono::seconds{10};
    const auto closed=expire ? plan.poll() : plan.action({},exit);
    check(closed.size()==4 && closed[0]==Bytes({0x31,0x40,0x34,0x12,0xff}) && closed[1][4]==1 &&
        !shop->active(),"shop_close_did_not_resume_boss");
    check(plan.poll().empty(),"shop_timeout_repeated");
    check(plan.retired_action(exit) && plan.retired_action(Bytes{0x31,0,0x69,0x45,0,0xcc}),"late_shop_action_not_retired");
    plan.disconnected(); check(!plan.retired_action(exit),"closed_session_accepts_shop_replay");
}
}
int main(int argc,char** argv) {
    try {
        check(argc==2,"resource_root_required");
        awarded_card_drives_move_without_second_roll(std::filesystem::path(argv[1]));
        discarded_stack_cannot_be_used_and_does_not_end_turn(std::filesystem::path(argv[1]));
        purchase_timeout_resumes_turn_and_retires_old_click(std::filesystem::path(argv[1]));
        purchase_timeout_resumes_turn_and_retires_old_click(std::filesystem::path(argv[1]),146,162,0);
        shop_closes_without_waiting_for_client_timeout_ack(std::filesystem::path(argv[1]),false);
        shop_closes_without_waiting_for_client_timeout_ack(std::filesystem::path(argv[1]),true);
        std::cout<<"PASS actual chance award, rejected-use recovery and immediate selected-die movement\n";
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
