#include "richonline_opening_hand.hpp"
#include <algorithm>
#include <bit>

namespace richnet {
namespace {
void validate(const RichonlineInventoryPrefix4019& value,std::size_t actor_count) {
    // Actor indices in the consumer are signed and have no native bounds check.
    if(actor_count==0 || actor_count>8 || value.actor<0 || static_cast<std::size_t>(value.actor)>=actor_count)
        throw CodecError("richonline_inventory_actor_invalid");
    for(const auto& slot:value.slots) {
        if((slot.card_id==-1 && slot.count!=0) || (slot.card_id!=-1 && (slot.card_id<=0 || slot.count<=0)))
            throw CodecError("richonline_inventory_slot_invalid");
    }
}
}
Bytes encode_richonline_inventory_prefix4019(const RichonlineInventoryPrefix4019& value,std::size_t actor_count) {
    validate(value,actor_count);
    Bytes plain; plain.reserve(30); append_le(plain,0x4019,2); append_le(plain,value.game_id,2);
    append_le(plain,static_cast<std::uint16_t>(value.actor),2);
    for(std::size_t i=0;i<value.slots.size();++i) {
        append_le(plain,static_cast<std::uint16_t>(value.slots[i].card_id),2);
        append_le(plain,static_cast<std::uint16_t>(value.slots[i].count),2);
        plain.insert(plain.end(),value.slot_tail[i].begin(),value.slot_tail[i].end());
    }
    return plain;
}
RichonlineInventoryPrefix4019 decode_richonline_inventory_prefix4019(View plain,std::size_t actor_count) {
    if(plain.size()!=30 || read_le(plain.first(2))!=0x4019) throw CodecError("richonline_inventory_prefix_length_invalid");
    RichonlineInventoryPrefix4019 value{};
    value.game_id=static_cast<std::uint16_t>(read_le(plain.subspan(2,2)));
    value.actor=std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(4,2))));
    for(std::size_t i=0;i<value.slots.size();++i) {
        value.slots[i].card_id=std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(6+6*i,2))));
        value.slots[i].count=std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(plain.subspan(8+6*i,2))));
        value.slot_tail[i]={plain[10+6*i],plain[11+6*i]};
    }
    validate(value,actor_count); return value;
}
RichonlineOpeningHandPlan prepare_richonline_opening_hand(std::uint16_t game_id,
    const RichonlineMapOpeningHand& configured,const RichonlineChanceResources& resources) {
    RichonlineOpeningHandPlan plan{};
    const std::array<const std::vector<RichonlineMapOpeningCard>*,2> hands{&configured.human,&configured.boss};
    for(std::size_t actor=0;actor<hands.size();++actor) {
        // 4019 cannot initialize a fifth slot; reject this unsupported configuration rather than truncate.
        if(hands[actor]->size()>4) throw CodecError("richonline_opening_hand_prefix_capacity");
        std::size_t slot=0;
        for(const auto& card:*hands[actor]) {
            if(card.card_id<=0 || card.count<=0 || !resources.contains_card(card.card_id))
                throw CodecError("richonline_opening_hand_card_invalid");
            // The receiver memcpy does not call the acquire/combination path.
            plan.inventories[actor][slot++]={card.card_id,card.count};
        }
        if(std::any_of(plan.inventories[actor].begin()+4,plan.inventories[actor].end(),
            [](const auto& slot){return slot.card_id!=-1 || slot.count!=0;}))
            throw CodecError("richonline_opening_hand_prefix_capacity");
        RichonlineInventoryPrefix4019 packet{game_id,static_cast<std::int16_t>(actor),{}, {}};
        std::copy_n(plan.inventories[actor].begin(),4,packet.slots.begin());
        // NEW 7D5BD0 initializes these two slot bytes to 0 and -1; their gameplay meaning remains unknown.
        packet.slot_tail.fill({0,255});
        plan.synchronization[actor]=encode_richonline_inventory_prefix4019(packet,2);
    }
    return plan;
}
}
