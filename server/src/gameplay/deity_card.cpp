#include "richonline_deity_card.hpp"

namespace richnet {
namespace {
void validate(const RichonlineDeityCardRequest& r) {
    if((r.kind!=RichonlineDeityCard::summon1047 && r.kind!=RichonlineDeityCard::dismiss1048) ||
        r.slot<0 || r.slot>=8 || r.bank!=0 || r.target_actor<0 || r.target_actor>=8)
        throw CodecError("richonline_deity_card_fields_invalid");
}
}
RichonlineDeityCardRequest parse_richonline_deity_card(View bytes) {
    if(bytes.size()!=8) throw CodecError("richonline_deity_card_wire_invalid");
    RichonlineDeityCardRequest r{static_cast<RichonlineDeityCard>(read_le(bytes.first(2))),
        static_cast<std::uint16_t>(read_le(bytes.subspan(2,2))),static_cast<std::int8_t>(bytes[4]),
        static_cast<std::int8_t>(bytes[5]),static_cast<std::int8_t>(bytes[6]),bytes[7]};
    validate(r);return r;
}
RichonlineDeityCardPlan plan_richonline_deity_card(std::uint16_t game,
    const RichonlineDeityCardRequest& r,std::uint16_t calendar,
    const RichonlineDeityCardTarget& target,const std::optional<RichonlineSummonedNpc>& npc,
    const RichonlineBossCards& cards,std::uint8_t active_actor) {
    validate(r);
    if(active_actor>=8) throw CodecError("richonline_deity_card_active_actor_invalid");
    if(r.calendar!=calendar) throw CodecError("richonline_deity_card_calendar_mismatch");
    if(target.actor!=r.target_actor || !target.active || !target.in_target_selection)
        throw CodecError("richonline_deity_card_target_invalid");
    const bool summon=r.kind==RichonlineDeityCard::summon1047;
    if(summon) {
        // NEW6926A0 permits gods0..7 and18; other NPCs must not be attached.
        if(!npc || !npc->present || !npc->visible || npc->position<0 ||
            !((npc->id>=0 && npc->id<8) || npc->id==18) || npc->affix_turns>127)
            throw CodecError("richonline_deity_card_ground_npc_invalid");
    } else if(npc || !target.status.possession) {
        throw CodecError("richonline_deity_card_no_possession");
    }
    const auto consumption=cards.prepare_consumption(r.slot,summon ? 1047 : 1048);
    if(!consumption) throw CodecError("richonline_deity_card_not_owned");
    auto after=target;
    auto continuation=RichonlineDeityCardContinuation::restore_action;
    Bytes response;append_le(response,summon ? 0x40c0 : 0x40c1,2);append_le(response,game,2);
    response.push_back(static_cast<std::uint8_t>(r.slot));response.push_back(static_cast<std::uint8_t>(r.bank));
    if(summon) {
        append_le(response,static_cast<std::uint16_t>(npc->position),2);
        after.status.possession=npc->id;
        if(target.actor==active_actor) switch(npc->id) {
        case 0:case 1:continuation=RichonlineDeityCardContinuation::await_money34;break;
        case 2:continuation=RichonlineDeityCardContinuation::send_lost_cards4024;break;
        case 3:continuation=RichonlineDeityCardContinuation::send_fortune4023;break;
        case 7:continuation=RichonlineDeityCardContinuation::resolve_sleepwalking;break;
        default:break;
        }
        // Case7 has protection/status branches for both current and other
        // actors in66EB40; it cannot be treated as attachment-only.
        if(npc->id==7) continuation=RichonlineDeityCardContinuation::resolve_sleepwalking;
    } else after.status.possession.reset();
    response.push_back(static_cast<std::uint8_t>(target.actor));
    return {std::move(response),*consumption,target,after,npc,
        summon ? npc->affix_turns : std::uint8_t{0},continuation};
}
}
