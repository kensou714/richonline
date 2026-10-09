#include "richonline_hibernate_card.hpp"
#include <iostream>

using namespace richnet;
namespace {
void check(bool v,const char* message) {if(!v) throw std::runtime_error(message);}
template<class F> void rejects(F f) {try {f();} catch(const CodecError&) {return;}throw std::runtime_error("expected rejection");}
RichonlineHibernateSnapshot fixture() {
    RichonlineHibernateSnapshot s{};s.game_id=0x4567;s.calendar=0x1234;s.active_actor=0;s.roll_phase=true;s.active_actor_can_act=true;
    for(std::size_t i=0;i<8;++i) {
        auto& a=s.actors[i];a.present=i<3;a.inventory.actor=static_cast<std::uint8_t>(i);a.inventory.owner_actor=static_cast<std::uint8_t>(i);
        a.relations1472.fill(7);a.status.possession=3;a.status.one_step=2;
    }
    s.actors[0].inventory.main[3]={506,2};return s;
}
void run(const std::filesystem::path& root) {
    const auto resources=RichonlineChanceResources::load(root);
    const auto rules=RichonlineHibernateRules::load(root);check(rules.frozen_turns==2,"real GValue30");
    const Bytes wire{164,0,0x34,0x12,3,0};const auto r=decode_richonline_hibernate164(wire);
    check(r.calendar==0x1234 && r.inventory_slot==3 && r.inventory_bank==0,"decode");
    check(encode_richonline_hibernate40f4(0x4567,r)==Bytes({0xf4,0x40,0x67,0x45,3,0}),"encode");
    for(std::size_t n=0;n<6;++n) rejects([&]{decode_richonline_hibernate164(View(wire).first(n));});
    auto wrong=wire;wrong.push_back(0);rejects([&]{decode_richonline_hibernate164(wrong);});
    wrong=wire;wrong[0]=160;rejects([&]{decode_richonline_hibernate164(wrong);});
    for(const auto value:{8,255}) {wrong=wire;wrong[4]=static_cast<std::uint8_t>(value);rejects([&]{decode_richonline_hibernate164(wrong);});}
    for(const auto value:{1,255}) {wrong=wire;wrong[5]=static_cast<std::uint8_t>(value);rejects([&]{decode_richonline_hibernate164(wrong);});}
    const auto before=fixture();
    const auto plan=[&](const RichonlineHibernateSnapshot& s,std::string_view map="BS_1_1.emp") {
        return plan_richonline_hibernate(r,0x4567,0,map,resources,rules,s);
    };
    const auto p=plan(before);
    check(p.before==before && p.after.actors[0].inventory.main[3].count==1,"immutable consume");
    check(p.after.actors[0].status==before.actors[0].status,"requester unchanged");
    check(p.after.actors[1].status.frozen==2 && p.after.actors[2].status.frozen==2,"freeze targets");
    auto unrelated=p.after.actors[1].status;unrelated.frozen=0;check(unrelated==before.actors[1].status,"preserve unrelated status");
    check(p.after.actors[1].relations1472[0]==0 && p.after.actors[0].relations1472[1]==0 && p.after.actors[1].relations1472[2]==7,"bidirectional relations");
    check(p.after.actors[3]==before.actors[3],"absent preserved");
    auto s=before;s.game_id++;rejects([&]{plan(s);});s=before;s.calendar++;rejects([&]{plan(s);});
    s=before;s.active_actor=1;rejects([&]{plan(s);});s=before;s.roll_phase=false;rejects([&]{plan(s);});
    s=before;s.active_actor_can_act=false;rejects([&]{plan(s);});
    rejects([&]{plan_richonline_hibernate(r,0x4567,-1,"BS_1_1.emp",resources,rules,before);});
    s=before;s.actors[0].inventory.owner_actor=1;rejects([&]{plan(s);});
    s=before;s.actors[0].inventory.main[3]={507,1};rejects([&]{plan(s);});
    s=before;s.actors[0].inventory.main[3]={506,0};rejects([&]{plan(s);});
    s=before;s.actors[1].present=false;s.actors[2].present=false;rejects([&]{plan(s);});
    for(auto field:{&RichonlineHibernateActor::raw1493,&RichonlineHibernateActor::raw1494,&RichonlineHibernateActor::raw1495,&RichonlineHibernateActor::raw1497}) {
        for(const auto value:{0,1,-2}) {s=before;s.actors[1].*field=static_cast<std::int8_t>(value);const auto excluded=plan(s);check(excluded.after.actors[1]==s.actors[1],"raw != -1 exclusion");}
        s=before;s.actors[0].*field=0;rejects([&]{plan(s);});
    }
    s=before;s.actors[1].status.frozen=1;check(plan(s).after.actors[1]==s.actors[1],"already frozen exclusion");
    s=before;s.actors[1].status.protected_from_status=true;s.actors[1].inventory.main[0]={1071,2};
    auto protected_plan=plan(s);check(protected_plan.effects[1]==RichonlineHibernateEffect::status_immunity && protected_plan.after.actors[1].inventory==s.actors[1].inventory,"status immunity");
    s=before;s.actors[1].inventory.main[1]={1071,2};protected_plan=plan(s);
    check(protected_plan.effects[1]==RichonlineHibernateEffect::passive_protection && protected_plan.after.actors[1].status.frozen==0 && protected_plan.after.actors[1].inventory.main[1].count==1 && protected_plan.consumed_protection[1]->bank==0,"main protection");
    auto protection_commit=s;commit_richonline_hibernate(protection_commit,protected_plan);
    check(protection_commit.actors[0].inventory.main[3].count==1 && protection_commit.actors[1].inventory.main[1].count==1 && protection_commit.actors[1].status.frozen==0,"selected and passive atomic commit");
    auto stale_protection=s;stale_protection.actors[1].inventory.main[1].count=1;
    const auto stale_protection_before=stale_protection;
    rejects([&]{commit_richonline_hibernate(stale_protection,protected_plan);});
    check(stale_protection==stale_protection_before && stale_protection.actors[0].inventory.main[3].count==2,"passive CAS rejection preserves selected card and all statuses");
    s=before;s.actors[1].inventory.equipment=RichonlineProtectionEquipment{};s.actors[1].inventory.equipment_search_enabled=true;(*s.actors[1].inventory.equipment)[2]={1071,1,0};protected_plan=plan(s);
    check(protected_plan.consumed_protection[1]->bank==1 && (*protected_plan.after.actors[1].inventory.equipment)[2].card_id==-1,"equipment protection");
    const auto restricted=RichonlineChanceResources::parse("x.emp\t5\t0\t0\t0\t0\t0\t506\timg\ttext\n","[PROP]\nindx=506\ntype=CARD\nenable=true\n[PROP]\nindx=1071\ntype=CARD\nenable=true\n","",{{"x.emp",{506}}});
    const auto not_allowed=plan_richonline_hibernate(r,0x4567,0,"x.emp",restricted,rules,s);
    check(not_allowed.after.actors[1].status.frozen==2 && not_allowed.after.actors[1].inventory==s.actors[1].inventory,"map protection gate");
    auto timer=p.after.actors[1].status;check(richonline_hibernate_begin_turn(timer) && timer.frozen==1,"first skip");check(!richonline_hibernate_begin_turn(timer) && timer.frozen==0,"zero resumes");check(!richonline_hibernate_begin_turn(timer),"resume");
    s=before;commit_richonline_hibernate(s,p);check(s==p.after,"CAS commit");const auto committed=s;rejects([&]{commit_richonline_hibernate(s,p);});check(s==committed,"CAS atomic");
    s=before;s.actors[2].relations1472[1]++;const auto stale=s;rejects([&]{commit_richonline_hibernate(s,p);});check(s==stale,"CAS relation mismatch");
    for(const auto text:{"", "[ITEM]\nindx=30\nvalue=0\n","[ITEM]\nindx=30\nvalue=128\n","[ITEM]\nindx=30\nvalue=2\n[ITEM]\nindx=30\nvalue=2\n"}) rejects([&]{RichonlineHibernateRules::parse(text);});
}
}
int main(int argc,char** argv) {
    try {if(argc!=2) throw std::runtime_error("resource root required");run(argv[1]);std::cout<<"PASS hibernate164/40F4 strict codec, ownership, raw gates, GValue30, protection, bidirectional relations, frozen turns and atomic CAS\n";}
    catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
