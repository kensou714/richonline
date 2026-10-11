#include "richonline_theft_card.hpp"
#include "lua_wire.hpp"

namespace richnet {
RichonlineTheftRequest decode_richonline_theft_request(View packet) {
    if(packet.size()!=8 || read_le(packet.first(2))!=116 || packet[4]>=8 || packet[5]!=0 ||
        packet[6]>=4 || packet[7]>=8) throw CodecError("richonline_theft_request_invalid");
    return {static_cast<std::uint16_t>(read_le(packet.subspan(2,2))),packet[4],packet[6],packet[7]};
}
RichonlineTheftPlan prepare_richonline_theft(const RichonlineTheftRequest& request,
    const RichonlinePlayerCards& attacker,const RichonlinePlayerCards& victim,
    const RichonlineChanceResources& resources,bool secondary_absent,const std::shared_ptr<LuaServer>& script) {
    if(&attacker==&victim || attacker.actor_slot()==victim.actor_slot() ||
        request.target!=victim.actor_slot() || request.inventory_slot>=8 || request.target_slot>=8 ||
        attacker.game_mode()!=0 || victim.game_mode()!=0 || attacker.game_id()!=victim.game_id() ||
        attacker.map_name()!=victim.map_name()) throw CodecError("richonline_theft_context_invalid");
    if(!resources.automatic_card_eligible(attacker.map_name(),1053))
        throw CodecError("richonline_theft_card_not_allowed");
    const auto validate=[&](const RichonlineChanceInventory& inventory) {
        for(const auto& slot:inventory)
            if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 &&
                (slot.count<1 || slot.count>127 || !resources.contains_card(slot.card_id))))
                throw CodecError("richonline_theft_inventory_invalid");
    };
    validate(attacker.inventory());validate(victim.inventory());
    const auto consumed=attacker.prepare_consumption(static_cast<std::int8_t>(request.inventory_slot),1053);
    if(!consumed) throw CodecError("richonline_theft_card_not_owned");
    const auto stolen=victim.inventory()[request.target_slot].card_id;
    if(stolen==-1) throw CodecError("richonline_theft_victim_slot_empty");
    RichonlineTheftPlan plan;
    plan.attacker_=&attacker;plan.victim_=&victim;
    plan.attacker_before_=attacker.inventory();plan.victim_before_=victim.inventory();
    plan.attacker_after_=consumed->remaining_inventory;plan.victim_after_=plan.victim_before_;
    const bool protection_eligible=resources.automatic_card_eligible(attacker.map_name(),1074);
    if(protection_eligible) {
        for(std::uint8_t slot=0;slot<plan.victim_before_.size();++slot)
            if(plan.victim_before_[slot].card_id==1074) {plan.protection_slot_=static_cast<std::int8_t>(slot);break;}
        if(plan.protection_slot_<0 && !secondary_absent)
            throw CodecError("richonline_theft_secondary_protection_unknown");
    }
    if(plan.protection_slot_>=0) {
        auto& slot=plan.victim_after_[static_cast<std::size_t>(plan.protection_slot_)];
        if(--slot.count==0) slot={};
    } else {
        // 客户端先向施放者插入一张，再扣目标一张；满包时仍扣目标，插入及合成沿用资源规则。
        plan.transferred_card_=stolen;
        plan.attacker_after_=resources.add(attacker.map_name(),stolen,1,plan.attacker_after_);
        auto& slot=plan.victim_after_[request.target_slot];
        if(--slot.count==0) slot={};
    }
    append_le(plan.response_,0x40c4,2);append_le(plan.response_,attacker.game_id(),2);
    plan.response_.insert(plan.response_.end(),{request.inventory_slot,0,request.target,request.target_slot});
    if(script) {
        auto inventory=LuaValue::array();
        for(const auto& slot:plan.victim_before_) inventory.push_back({{"card",slot.card_id},{"count",slot.count}});
        const auto result=script->call("card.theft",{{"game_id",attacker.game_id()},
            {"inventory_slot",request.inventory_slot},{"target",request.target},{"target_slot",request.target_slot},
            {"inventory",std::move(inventory)},{"protection_eligible",protection_eligible},
            {"secondary_protection_absent",secondary_absent}});
        const LuaValue expected{{"protection_slot",plan.protection_slot_},{"transferred_card",plan.transferred_card_},
            {"message",lua_bytes(View(plan.response_))}};
        if(result!=expected || !result.at("protection_slot").is_number_integer() ||
            !result.at("transferred_card").is_number_integer()) throw CodecError("lua_theft_plan_invalid");
    }
    return plan;
}
bool commit_richonline_theft(RichonlinePlayerCards& attacker,RichonlinePlayerCards& victim,
    const RichonlineTheftPlan& plan) noexcept {
    if(plan.attacker_!=&attacker || plan.victim_!=&victim || attacker.inventory()!=plan.attacker_before_ ||
        victim.inventory()!=plan.victim_before_) return false;
    attacker.commit_inventory(plan.attacker_after_);victim.commit_inventory(plan.victim_after_);return true;
}
}
