#include "richonline_collision.hpp"
#include "lua_server.hpp"
#include <algorithm>

namespace richnet {
namespace {
void verify_script(const RichonlineCollisionPlan& plan,std::uint8_t active,std::uint32_t mode,
    bool suppressed,const std::shared_ptr<LuaServer>& script) {
    if(!script) return;
    auto actors=LuaValue::array();
    for(const auto& actor:plan.before) {
        auto inventory=LuaValue::array();
        for(const auto& slot:actor.inventory) inventory.push_back({{"card",slot.card_id},{"count",slot.count}});
        actors.push_back({{"slot",actor.slot},{"position",actor.position},{"active",actor.active},
            {"synthetic",actor.synthetic},{"excluded",actor.excluded1497},
            {"possession",actor.possession ? static_cast<int>(*actor.possession) : -1},{"inventory",std::move(inventory)}});
    }
    auto transfers=LuaValue::array();
    for(const auto& item:plan.transfers) transfers.push_back({{"source_actor",item.source_actor},
        {"target_actor",item.target_actor},{"source_slot",item.source_slot},{"card_id",item.card_id}});
    const LuaValue expected{{"evaluate_junction",plan.evaluate_junction},{"transfers",std::move(transfers)}};
    const auto result=script->call("collision.plan",{{"actor",active},{"mode",mode},
        {"suppressed",suppressed},{"actors",std::move(actors)}});
    if(result!=expected) throw CodecError("lua_collision_plan_invalid");
    for(const auto& item:result.at("transfers"))
        for(const auto* field:{"source_actor","target_actor","source_slot","card_id"})
            if(!item.at(field).is_number_integer()) throw CodecError("lua_collision_plan_integer_required");
}
}
RichonlineCollisionPlan plan_richonline_collision(std::uint8_t active,
    std::uint32_t mode,bool suppressed,std::span<const RichonlineCollisionActor> actors,
    const RichonlineChanceResources& resources,std::string_view map,std::shared_ptr<LuaServer> script) {
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
    if(suppressed || (mode==4 && owner.synthetic)) {
        plan.evaluate_junction=false;verify_script(plan,active,mode,suppressed,script);return plan;
    }
    if(owner.synthetic || owner.possession!=6) {verify_script(plan,active,mode,suppressed,script);return plan;}
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
    verify_script(plan,active,mode,suppressed,script);return plan;
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
