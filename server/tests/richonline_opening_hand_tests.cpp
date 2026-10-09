#include "richonline_opening_hand.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool ok,const char* reason) { if(!ok) throw std::runtime_error(reason); }
template<class Action> void rejected(Action action,const char* code) {
    try { action(); } catch(const CodecError& error) { check(std::string(error.what())==code,"opening_wrong_rejection"); return; }
    throw std::runtime_error("opening_missing_rejection");
}
void run(const std::filesystem::path& root) {
    const auto resources=RichonlineChanceResources::load(root);
    const auto& package=legacy_richonline_map_package();
    check(package.opening_hand.has_value(),"BS1_opening_policy_missing");
    const auto plan=prepare_richonline_opening_hand(0x1234,*package.opening_hand,resources);
    check(plan.inventories[0][0]==RichonlineChanceCardSlot{1038,1} &&
        plan.inventories[0][1]==RichonlineChanceCardSlot{1044,1},"opening_did_not_use_requested_resource_cards");
    for(std::size_t i=2;i<8;++i) check(plan.inventories[0][i]==RichonlineChanceCardSlot{},"opening_human_extra_card");
    for(const auto& slot:plan.inventories[1]) check(slot==RichonlineChanceCardSlot{},"opening_boss_received_inventory");
    const auto human=decode_richonline_inventory_prefix4019(plan.synchronization[0],2);
    check(plan.synchronization[0]==Bytes({0x19,0x40,0x34,0x12,0,0,
        0x0e,0x04,1,0,0,0xff,0x14,0x04,1,0,0,0xff,
        0xff,0xff,0,0,0,0xff,0xff,0xff,0,0,0,0xff}),"NEW_4019_golden_bytes_wrong");
    check(human.game_id==0x1234 && human.actor==0 && plan.synchronization[0].size()==30 &&
        human.slots[0]==RichonlineChanceCardSlot{1038,1} && human.slots[1]==RichonlineChanceCardSlot{1044,1},
        "NEW_4019_exact_prefix_wrong");
    const auto boss=decode_richonline_inventory_prefix4019(plan.synchronization[1],2);
    check(boss.actor==1,"NEW_4019_actor_offset_wrong");
    for(std::size_t i=0;i<4;++i) check(human.slot_tail[i]==std::array<std::uint8_t,2>{0,255} &&
        boss.slot_tail[i]==std::array<std::uint8_t,2>{0,255},"opening_constructor_tail_not_preserved");
    auto opaque=human; opaque.slot_tail[2]={0xa5,0x5a};
    check(decode_richonline_inventory_prefix4019(encode_richonline_inventory_prefix4019(opaque,2),2)==opaque,
        "inventory_unknown_tail_replaced");
    auto bad=human; bad.actor=-1;
    rejected([&]{encode_richonline_inventory_prefix4019(bad,2);},"richonline_inventory_actor_invalid");
    bad.actor=2; rejected([&]{encode_richonline_inventory_prefix4019(bad,2);},"richonline_inventory_actor_invalid");
    rejected([&]{encode_richonline_inventory_prefix4019(human,9);},"richonline_inventory_actor_invalid");
    auto truncated=plan.synchronization[0]; truncated.pop_back();
    rejected([&]{decode_richonline_inventory_prefix4019(truncated,2);},"richonline_inventory_prefix_length_invalid");
    auto extended=plan.synchronization[0]; extended.resize(54);
    rejected([&]{decode_richonline_inventory_prefix4019(extended,2);},"richonline_inventory_prefix_length_invalid");
    bad=human; bad.slots[2]={-1,1};
    rejected([&]{encode_richonline_inventory_prefix4019(bad,2);},"richonline_inventory_slot_invalid");
    bad=human; bad.slots[0].count=-1;
    rejected([&]{encode_richonline_inventory_prefix4019(bad,2);},"richonline_inventory_slot_invalid");
    auto configured=*package.opening_hand; configured.human.assign(5,{1038,1});
    rejected([&]{prepare_richonline_opening_hand(0x1234,configured,resources);},"richonline_opening_hand_prefix_capacity");
    configured.human={{32767,1}};
    rejected([&]{prepare_richonline_opening_hand(0x1234,configured,resources);},"richonline_opening_hand_card_invalid");
    configured.human={{1038,1},{1038,2},{1044,1},{1044,2}};
    const auto full=prepare_richonline_opening_hand(0x1234,configured,resources);
    for(std::size_t i=0;i<4;++i) check(full.inventories[0][i]==RichonlineChanceCardSlot{
        configured.human[i].card_id,configured.human[i].count},"opening_memcpy_unexpectedly_combined_cards");
    check(prepare_richonline_opening_hand(0x1234,*package.opening_hand,resources).synchronization==plan.synchronization,
        "pure_opening_planner_changed_inventory_or_randomized");
}
}
int main(int argc,char** argv) {
    try { check(argc==2,"NEW_resource_root_required"); run(argv[1]);
        std::cout<<"PASS NEW opening hand exact 4019 first-four-slot codec, resource cards, actor bounds and pure planning\n";
    } catch(const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
