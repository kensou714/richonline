#include "richonline_ground_card.hpp"
#include <utility>

namespace richnet {
namespace {
void validate_request(const RichonlineGroundCardRequest& request) {
    if(request.kind!=RichonlineGroundCard::banana507 && request.kind!=RichonlineGroundCard::roadblock1043 &&
        request.kind!=RichonlineGroundCard::supermine500)
        throw CodecError("richonline_ground_card_kind_invalid");
    if(request.inventory_slot<0 || request.inventory_slot>=8 || request.inventory_bank!=0 || request.position<0)
        throw CodecError("richonline_ground_card_request_fields_invalid");
}
bool forbidden_static(std::int8_t type) noexcept {
    return type==2 || type==3 || type==28 || type==58 || type==61;
}
void validate_context(const RichonlineGroundCardTurnContext& context) {
    if(context.active_actor<0 || context.active_actor>=8 || context.requesting_actor<0 || context.requesting_actor>=8)
        throw CodecError("richonline_ground_card_actor_invalid");
    if(context.active_actor!=context.requesting_actor)
        throw CodecError("richonline_ground_card_not_active_actor");
    if(!context.roll_phase)
        throw CodecError("richonline_ground_card_not_roll_phase");
    if(!context.requesting_actor_can_act)
        throw CodecError("richonline_ground_card_actor_controlled");
    if(!context.target_is_map_cell || !context.target_is_walkable)
        throw CodecError("richonline_ground_card_target_not_walkable");
    if(!context.target_visible)
        throw CodecError("richonline_ground_card_target_not_visible");
    if(context.target_has_actor)
        throw CodecError("richonline_ground_card_target_actor_occupied");
    if(forbidden_static(context.target_static_type))
        throw CodecError("richonline_ground_card_target_static_forbidden");
}
}

RichonlineGroundCardRequest decode_richonline_ground_card165(View plain) {
    if(plain.size()!=8) throw CodecError("richonline_ground_card_request_length");
    if(read_le(plain.first(2))!=165) throw CodecError("richonline_ground_card_request_opcode");
    const RichonlineGroundCardRequest request{RichonlineGroundCard::banana507,
        static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),
        static_cast<std::int8_t>(plain[4]), static_cast<std::int8_t>(plain[5]),
        static_cast<std::int16_t>(read_le(plain.subspan(6,2)))};
    validate_request(request);
    return request;
}

RichonlineGroundCardRequest decode_richonline_roadblock108(View plain) {
    if(plain.size()!=8 || read_le(plain.first(2))!=108)
        throw CodecError("richonline_roadblock_request_invalid");
    const RichonlineGroundCardRequest request{RichonlineGroundCard::roadblock1043,
        static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),
        static_cast<std::int8_t>(plain[4]),static_cast<std::int8_t>(plain[5]),
        static_cast<std::int16_t>(read_le(plain.subspan(6,2)))};
    validate_request(request);
    return request;
}

RichonlineGroundCardRequest decode_richonline_supermine158(View plain) {
    if(plain.size()!=8 || read_le(plain.first(2))!=158) throw CodecError("richonline_supermine_request_invalid");
    RichonlineGroundCardRequest request{RichonlineGroundCard::supermine500,
        static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),
        static_cast<std::int8_t>(plain[4]),static_cast<std::int8_t>(plain[5]),
        static_cast<std::int16_t>(read_le(plain.subspan(6,2)))};
    validate_request(request);return request;
}
Bytes encode_richonline_banana40f5(std::uint16_t game_id,const RichonlineGroundCardRequest& request) {
    validate_request(request);
    Bytes result;
    append_le(result,request.kind==RichonlineGroundCard::supermine500 ? 0x40ee :
        request.kind==RichonlineGroundCard::roadblock1043 ? 0x40bc : 0x40f5,2);
    append_le(result,game_id,2);
    result.push_back(static_cast<std::uint8_t>(request.inventory_slot));
    result.push_back(static_cast<std::uint8_t>(request.inventory_bank));
    append_le(result,static_cast<std::uint16_t>(request.position),2);
    return result;
}

RichonlineGroundCardPlan plan_richonline_banana_card(const RichonlineGroundCardRequest& request,
    const RichonlineGroundCardTurnContext& context,const RichonlineChanceInventory& inventory,
    const RichonlineGroundSnapshot& ground) {
    validate_request(request);
    validate_context(context);
    if(request.calendar!=context.calendar)
        throw CodecError("richonline_ground_card_calendar_mismatch");
    const auto slot=static_cast<std::size_t>(request.inventory_slot);
    if(inventory[slot].card_id!=static_cast<std::int16_t>(request.kind) || inventory[slot].count<=0)
        throw CodecError("richonline_ground_card_not_owned");
    if(ground.objects.contains(request.position))
        throw CodecError("richonline_ground_card_target_dynamic_occupied");

    auto after_inventory=inventory;
    if(--after_inventory[slot].count==0) after_inventory[slot]={};
    auto after_ground=ground.objects;
    // NEW679760 leaves the dynamic object's two metadata bytes at -1.
    const auto object=request.kind==RichonlineGroundCard::supermine500 ?
        RichonlineGroundObject{27,static_cast<std::uint8_t>(context.active_actor),3} :
        request.kind==RichonlineGroundCard::roadblock1043 ?
        RichonlineGroundObject{11,static_cast<std::uint8_t>(context.active_actor),255} :
        RichonlineGroundObject{30,255,255};
    after_ground.emplace(request.position,object);
    return {request,ground,std::move(after_ground),inventory,std::move(after_inventory),
        encode_richonline_banana40f5(context.game_id,request)};
}
} // namespace richnet
