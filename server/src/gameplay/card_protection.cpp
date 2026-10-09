#include "richonline_card_protection.hpp"

namespace richnet {
RichonlineAutomaticSleepProtection resolve_richonline_sleep_protection(std::string_view map,
    const RichonlineChanceResources& resources,const RichonlineProtectionInventory& inventory,
    const RichonlineActorStatus& status) {
    if(inventory.actor>=8 || inventory.owner_actor!=inventory.actor)
        throw CodecError("richonline_protection_inventory_owner_invalid");
    const auto valid=[&](std::int16_t id,std::int16_t count) {
        return id==-1 ? count==0 : id>=0 && count>0 && resources.is_card_type(id);
    };
    for(const auto& slot:inventory.main) if(!valid(slot.card_id,slot.count))
        throw CodecError("richonline_protection_inventory_invalid");
    if(inventory.equipment) for(const auto& slot:*inventory.equipment)
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.card_id<0 || slot.count<=0)))
            throw CodecError("richonline_protection_equipment_invalid");
    RichonlineAutomaticSleepProtection plan{inventory,inventory,{}};
    // NEW6106FC's skill/status protection branch precedes7CD440's card search.
    if(status.protected_from_status) return plan;
    for(std::size_t i=0;i<inventory.main.size();++i) if(inventory.main[i].card_id==1071) {
        if(!resources.automatic_card_eligible(map,1071)) return plan;
        auto& slot=plan.after.main[i];if(--slot.count==0) slot={};
        plan.consumed=RichonlineProtectionCardSource{static_cast<std::uint8_t>(i),0};return plan;
    }
    if(inventory.equipment_search_enabled && inventory.equipment) {
        for(std::size_t i=0;i<inventory.equipment->size();++i) {
            const auto& item=(*inventory.equipment)[i];
            if(item.card_id!=1071 || item.exclusion4!=0) continue;
            if(!resources.automatic_card_eligible(map,1071)) return plan;
            auto& slot=(*plan.after.equipment)[i];if(--slot.count==0) {slot.card_id=-1;slot.count=0;}
            plan.consumed=RichonlineProtectionCardSource{static_cast<std::uint8_t>(i),1};return plan;
        }
    }
    return plan;
}
RichonlineSleepProtection RichonlineAutomaticSleepProtection::main_inventory_projection() const {
    if(consumed && consumed->bank!=0) throw CodecError("richonline_protection_equipment_bridge_unimplemented");
    return {consumed.has_value(),consumed ? std::optional{consumed->slot} : std::nullopt};
}
void commit_richonline_sleep_protection(RichonlineProtectionInventory& current,const RichonlineAutomaticSleepProtection& plan) {
    if(current!=plan.before) throw CodecError("richonline_protection_inventory_changed");
    current=plan.after;
}
}
