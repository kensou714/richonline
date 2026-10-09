#include "richonline_collision.hpp"
#include <algorithm>

namespace richnet {
RichonlineCollisionPlan plan_richonline_collision(std::uint8_t active,
    std::uint32_t mode,bool suppressed,std::span<const RichonlineCollisionActor> actors,
    const RichonlineChanceResources& resources,std::string_view map) {
    if(actors.empty() || actors.size()>8 || active>=actors.size())
        throw CodecError("richonline_collision_context_invalid");
    for(std::size_t i=0;i<actors.size();++i) {
        const auto& actor=actors[i];
        if(actor.slot!=i || (actor.active && actor.position<0) ||
            (actor.possession && (*actor.possession<0 || *actor.possession>32)))
            throw CodecError("richonline_collision_actor_invalid");
        for(const auto& slot:actor.inventory)
            if((slot.card_id==-1 && slot.count!=0) ||
                (slot.card_id!=-1 && (slot.count<=0 || !resources.contains_card(slot.card_id))))
                throw CodecError("richonline_collision_inventory_invalid");
    }
    if(!actors[active].active) throw CodecError("richonline_collision_active_actor_invalid");
    RichonlineCollisionPlan plan{{actors.begin(),actors.end()},{actors.begin(),actors.end()},{},true};
    const auto& owner=actors[active];
    if(suppressed || (mode==4 && owner.synthetic)) {plan.evaluate_junction=false;return plan;}
    if(owner.synthetic || owner.possession!=6) return plan;
    for(std::size_t i=0;i<actors.size();++i) {
        const auto& other=actors[i];
        if(i==active || !other.active || other.synthetic || other.excluded1497 || other.position!=owner.position) continue;
        auto& inventory=plan.after[i].inventory;
        for(std::size_t slot=0;slot<inventory.size();++slot) if(inventory[slot].card_id!=-1) {
            const auto card=inventory[slot].card_id;
            // NEW consumes one from the first occupied slot even if the
            // receiving inventory is full. Addition may synthesize cards.
            if(--inventory[slot].count==0) inventory[slot]={};
            plan.after[active].inventory=resources.add(map,card,1,plan.after[active].inventory);
            plan.transfers.push_back({static_cast<std::uint8_t>(i),active,static_cast<std::uint8_t>(slot),card});
            break;
        }
    }
    return plan;
}
void commit_richonline_collision(std::span<RichonlineCollisionActor> actors,const RichonlineCollisionPlan& plan) {
    if(actors.size()!=plan.before.size() || plan.after.size()!=plan.before.size() ||
        !std::equal(actors.begin(),actors.end(),plan.before.begin()))
        throw CodecError("richonline_collision_state_changed");
    std::copy(plan.after.begin(),plan.after.end(),actors.begin());
}
bool richonline_boss_collision_allows_shared_landing(std::uint32_t mode,std::uint8_t active,
    std::span<const RichonlineCollisionActor> actors) {
    return mode==3 && actors.size()==2 && active<2 && actors[0].slot==0 && actors[1].slot==1 &&
        actors[0].active && actors[1].active && actors[0].synthetic!=actors[1].synthetic &&
        actors[0].position>=0 && actors[0].position==actors[1].position;
}
}
