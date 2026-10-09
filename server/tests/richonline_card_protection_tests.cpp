#include "richonline_card_protection.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool v,const char* why){if(!v)throw std::runtime_error(why);}
template<class F> void rejects(F f,std::string_view why) {
    try{f();}catch(const CodecError& e){if(e.what()==why)return;throw;}throw std::runtime_error("missing rejection");
}
void run(const std::filesystem::path& root) {
    const auto real=RichonlineChanceResources::load(root);
    check(real.automatic_card_eligible("BS_1_1.emp",1071),"real1071 membership");
    RichonlineProtectionInventory inventory{0,0,{},std::nullopt,false};
    inventory.main[3]={1071,2};inventory.main[5]={1071,1};
    RichonlineActorStatus status;status.possession=7;
    const auto p=resolve_richonline_sleep_protection("BS_1_1.emp",real,inventory,status);
    const auto projection=p.main_inventory_projection();
    check(p.consumed && p.consumed->slot==3 && p.consumed->bank==0 && projection.triggered &&
        projection.consumed_inventory_slot==3 && p.after.main[3]==RichonlineChanceCardSlot{1071,1} &&
        p.after.main[5]==inventory.main[5] && inventory==p.before,"first slot/one stack/main bridge");
    auto changed_owner=inventory;changed_owner.owner_actor=1;
    rejects([&]{commit_richonline_sleep_protection(changed_owner,p);},"richonline_protection_inventory_changed");
    commit_richonline_sleep_protection(inventory,p);
    rejects([&]{commit_richonline_sleep_protection(inventory,p);},"richonline_protection_inventory_changed");
    status.protected_from_status=true;
    const auto protected_plan=resolve_richonline_sleep_protection("BS_1_1.emp",real,inventory,status);
    check(!protected_plan.consumed && protected_plan.before==protected_plan.after,"status protection consumed card");
    status.protected_from_status=false;
    auto foreign=inventory;foreign.actor=1;
    rejects([&]{resolve_richonline_sleep_protection("BS_1_1.emp",real,foreign,status);},"richonline_protection_inventory_owner_invalid");
    RichonlineProtectionInventory boss{1,1,{},std::nullopt,false};
    check(!resolve_richonline_sleep_protection("BS_1_1.emp",real,boss,status).consumed,"BOSS inherited human card");
    const auto fixture=RichonlineChanceResources::parse("x.emp\t5\t0\t0\t0\t0\t0\t1071\timg\ttext\n",
        "[PROP]\nindx=1071\ntype=CARD\nenable=false\n[PROP]\nindx=1072\ntype=FUNC\nenable=true\n",
        "",{{"x.emp",{1071,1072}},{"absent.emp",{1072}}});
    check(!fixture.contains_card(1071) && fixture.automatic_card_eligible("x.emp",1071) &&
        !fixture.automatic_card_eligible("x.emp",1072),"automatic ignores enable but requires type0");
    const auto disabled=resolve_richonline_sleep_protection("x.emp",fixture,inventory,status);
    check(disabled.consumed && disabled.after.main[3].card_id==-1,"disabled CARD1071 must trigger automatic effect");
    check(!resolve_richonline_sleep_protection("absent.emp",fixture,inventory,status).consumed,"card not in map still triggered");
    rejects([&]{resolve_richonline_sleep_protection("missing.emp",fixture,inventory,status);},"richonline_chance_map_membership_missing");
    RichonlineProtectionEquipment equipment{};equipment[2]={1071,2,1};equipment[4]={1071,3,0};
    RichonlineProtectionInventory equipped{0,0,{},equipment,true};
    const auto e=resolve_richonline_sleep_protection("x.emp",fixture,equipped,status);
    check(e.consumed && e.consumed->slot==4 && e.consumed->bank==1 &&
        (*e.after.equipment)[4].count==2 && (*e.after.equipment)[2].count==2,"bank1 exclusion or stack wrong");
    rejects([&]{e.main_inventory_projection();},"richonline_protection_equipment_bridge_unimplemented");
    equipped.equipment_search_enabled=false;
    check(!resolve_richonline_sleep_protection("x.emp",fixture,equipped,status).consumed,"equipment flag gate ignored");
    equipped.equipment_search_enabled=true;equipped.main[7]={1071,1};
    const auto priority=resolve_richonline_sleep_protection("x.emp",fixture,equipped,status);
    check(priority.consumed->bank==0 && priority.consumed->slot==7 && priority.after.equipment==priority.before.equipment,
        "main inventory lost priority to equipment");
}
}
int main(int argc,char** argv) {
    try{if(argc!=2)throw std::runtime_error("resource root required");run(argv[1]);
        std::cout<<"PASS NEW1071 automatic type0/map membership, actor ownership, main/equipment precedence and CAS\n";
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
