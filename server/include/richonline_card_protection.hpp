#pragma once
#include "richonline_actor_status.hpp"

namespace richnet {
struct RichonlineProtectionEquipmentSlot {
    std::int16_t card_id=-1,count=0;
    // NEW7F85C0 reads this profile-slot byte at+4, requiring zero. The
    // wider meaning is not inferred from an equipped item's name.
    std::int8_t exclusion4=0;
    bool operator==(const RichonlineProtectionEquipmentSlot&) const = default;
};
using RichonlineProtectionEquipment=std::array<RichonlineProtectionEquipmentSlot,8>;
struct RichonlineProtectionInventory {
    std::uint8_t actor,owner_actor;
    RichonlineChanceInventory main;
    std::optional<RichonlineProtectionEquipment> equipment;
    // NEW7CEF00→6A3A00 tests profile flags&0x1000==0; not has_profile.
    bool equipment_search_enabled;
    bool operator==(const RichonlineProtectionInventory&) const = default;
};
struct RichonlineProtectionCardSource {std::uint8_t slot,bank;};
struct RichonlineAutomaticSleepProtection {
    RichonlineProtectionInventory before,after;
    std::optional<RichonlineProtectionCardSource> consumed;
    // Existing NPC/chance planner accepts main-inventory slots only. This
    // bridge explicitly rejects bank1 rather than consuming a wrong actor.
    RichonlineSleepProtection main_inventory_projection() const;
};
RichonlineAutomaticSleepProtection resolve_richonline_sleep_protection(std::string_view map,
    const RichonlineChanceResources&,const RichonlineProtectionInventory&,const RichonlineActorStatus&);
void commit_richonline_sleep_protection(RichonlineProtectionInventory&,const RichonlineAutomaticSleepProtection&);
}
