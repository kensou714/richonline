#include "richonline_clear_card.hpp"
#include <utility>

namespace richnet {
namespace {
void validate_request(const RichonlineClearCardRequest& request) {
    if (request.inventory_slot < 0 || request.inventory_slot >= 8 || request.inventory_bank != 0)
        throw CodecError("richonline_clear_card_inventory_fields_invalid");
}
}
RichonlineClearCardRequest decode_richonline_clear_card160(View plain) {
    if (plain.size() != 6) throw CodecError("richonline_clear_card_length");
    if (read_le(plain.first(2)) != 160) throw CodecError("richonline_clear_card_opcode");
    const RichonlineClearCardRequest request{
        static_cast<std::uint16_t>(read_le(plain.subspan(2, 2))),
        static_cast<std::int8_t>(plain[4]), static_cast<std::int8_t>(plain[5])};
    validate_request(request);
    return request;
}
Bytes encode_richonline_clear40f0(std::uint16_t game_id, const RichonlineClearCardRequest& request) {
    validate_request(request);
    Bytes response;
    append_le(response, 0x40f0, 2);
    append_le(response, game_id, 2);
    response.push_back(static_cast<std::uint8_t>(request.inventory_slot));
    response.push_back(static_cast<std::uint8_t>(request.inventory_bank));
    return response;
}
RichonlineClearCardPlan plan_richonline_clear_card(const RichonlineClearCardRequest& request,
    const RichonlineClearCardContext& context, const RichonlineChanceInventory& inventory,
    const RichonlineGroundSnapshot& ground) {
    validate_request(request);
    if (context.active_actor < 0 || context.active_actor >= 8 ||
        context.requesting_actor < 0 || context.requesting_actor >= 8)
        throw CodecError("richonline_clear_card_actor_invalid");
    if (context.active_actor != context.requesting_actor)
        throw CodecError("richonline_clear_card_not_active_actor");
    if (!context.roll_phase) throw CodecError("richonline_clear_card_not_roll_phase");
    if (!context.requesting_actor_can_act) throw CodecError("richonline_clear_card_actor_controlled");
    if (request.calendar != context.calendar) throw CodecError("richonline_clear_card_calendar_mismatch");
    const auto slot = static_cast<std::size_t>(request.inventory_slot);
    if (inventory[slot].card_id != 502 || inventory[slot].count <= 0)
        throw CodecError("richonline_clear_card_not_owned");
    auto after_inventory = inventory;
    if (--after_inventory[slot].count == 0) after_inventory[slot] = {};
    // NEW7E2B80 removes every occupied dynamic record, including traps.
    return {request, ground, {}, inventory, std::move(after_inventory),
        encode_richonline_clear40f0(context.game_id, request)};
}
} // namespace richnet
