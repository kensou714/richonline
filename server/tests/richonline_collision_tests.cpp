#include "richonline_collision.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool v,const char* why) {if(!v) throw std::runtime_error(why);}
template<class F> void rejects(F f,std::string_view why) {
    try{f();}catch(const CodecError& e){if(e.what()==why)return;throw;}
    throw std::runtime_error("missing rejection");
}
void run(const std::filesystem::path& root) {
    const auto resources=RichonlineChanceResources::load(root);
    std::vector<RichonlineCollisionActor> actors{{0,99,true,false,false,6,{}},{1,99,true,true,false,{}, {}}};
    actors[1].inventory[3]={1044,2};
    for(std::uint8_t active=0;active<2;++active) {
        check(richonline_boss_collision_allows_shared_landing(3,active,actors),"BOSS overlap admission");
        const auto p=plan_richonline_collision(active,3,false,actors,resources,"BS_1_1.emp");
        check(p.transfers.empty() && p.before==p.after && p.evaluate_junction,"synthetic overlap invented theft/combat");
    }
    actors[1].synthetic=false;
    check(!richonline_boss_collision_allows_shared_landing(3,0,actors),"human collision falsely certified BOSS");
    const auto p=plan_richonline_collision(0,3,false,actors,resources,"BS_1_1.emp");
    check(p.transfers.size()==1 && p.transfers[0].source_slot==3 && p.after[1].inventory[3]==RichonlineChanceCardSlot{1044,1} &&
        p.after[0].inventory[0]==RichonlineChanceCardSlot{1044,1} && actors==p.before,"theft semantics");
    commit_richonline_collision(actors,p);
    rejects([&]{commit_richonline_collision(actors,p);},"richonline_collision_state_changed");
    actors[1].excluded1497=true;
    check(plan_richonline_collision(0,3,false,actors,resources,"BS_1_1.emp").transfers.empty(),"excluded actor stolen");
    actors[1].excluded1497=false;actors[1].position=100;
    check(plan_richonline_collision(0,3,false,actors,resources,"BS_1_1.emp").transfers.empty(),"different position stolen");
    actors[1].position=99;actors[0].possession.reset();
    check(plan_richonline_collision(0,3,false,actors,resources,"BS_1_1.emp").transfers.empty(),"ordinary collision invented theft");
    actors[0].possession=6;
    auto suppressed=plan_richonline_collision(0,3,true,actors,resources,"BS_1_1.emp");
    check(suppressed.transfers.empty() && !suppressed.evaluate_junction,"83830 suppression ignored");
    for(auto& slot:actors[0].inventory) slot={1038,1};
    const auto full=plan_richonline_collision(0,3,false,actors,resources,"BS_1_1.emp");
    check(full.after[0].inventory==actors[0].inventory && full.after[1].inventory[3].card_id==-1,
        "full bag must still consume donor card");
    actors.push_back({2,99,true,false,false,{}, {}});actors[2].inventory[7]={1046,3};
    const auto multiple=plan_richonline_collision(0,3,false,actors,resources,"BS_1_1.emp");
    check(multiple.transfers.size()==2 && multiple.transfers[0].source_actor==1 && multiple.transfers[1].source_actor==2 &&
        multiple.after[2].inventory[7]==RichonlineChanceCardSlot{1046,2},"multi occupant order");
    actors[2].slot=7;
    rejects([&]{plan_richonline_collision(0,3,false,actors,resources,"BS_1_1.emp");},"richonline_collision_actor_invalid");
}
}
int main(int argc,char** argv) {
    try{if(argc!=2)throw std::runtime_error("resources required");run(argv[1]);
        std::cout<<"PASS NEW same-position collision, NPC6 transfer, synthetic admission and CAS\n";
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
