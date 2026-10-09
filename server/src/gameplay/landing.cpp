#include "richonline_boss_landing.hpp"
#include <utility>
#include <limits>

namespace richnet {
std::optional<RichonlineLandingResult> resolve_richonline_controlled_static_landing(
    std::uint16_t game_id,const RichonlineLandingContext& context) {
    if(!richonline_landing_controlled(context.actor_status) || context.game_mode!=3 || context.property_ref!=-1)
        return {};
    const auto kind=context.static_type;
    // Exact NEW7E2730 classification, used by7C54B0 before its control guard.
    const bool special=(kind>=0 && kind<=10) || kind==28 || (kind>=41 && kind<=43) ||
        (kind>=51 && kind<=62) || (kind>=67 && kind<=70);
    if(!special) return {};
    if(context.actor_slot>=2 || context.synthetic_actor!=(context.actor_slot==1) || context.position<0 ||
        context.road_degree==0 || context.road_degree>4 ||
        (context.occupied_by_other_actor && !context.collision_resolved))
        throw CodecError("richonline_controlled_static_landing_invalid");
    Bytes stop; append_le(stop,0x4013,2); append_le(stop,game_id,2);
    append_le(stop,static_cast<std::uint16_t>(context.position),2);
    return RichonlineLandingResult{{std::move(stop)},RichonlineLandingProgress::complete};
}
RichonlineBossLandingState::RichonlineBossLandingState(std::uint16_t game_id,std::array<std::uint32_t,2> points)
    : game_id_(game_id) {
    for (const auto value : points)
        if (value>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
            throw CodecError("richonline_boss_points_out_of_range");
    ledger_=std::make_shared<RichonlineGameLedger>(std::vector<RichonlineGameFunds>{
        {0,{},points[0],{}},{0,{},points[1],{}}});
}
RichonlineBossLandingState::RichonlineBossLandingState(std::uint16_t game_id,std::shared_ptr<RichonlineGameLedger> ledger)
    : game_id_(game_id),ledger_(std::move(ledger)) {
    if (!ledger_ || ledger_->actor_count()!=2) throw CodecError("richonline_boss_landing_ledger_invalid");
}
std::array<std::uint32_t,2> RichonlineBossLandingState::points() const {
    return {ledger_->snapshot(0).funds.tickets,ledger_->snapshot(1).funds.tickets};
}
void RichonlineBossLandingState::validate_landing(const RichonlineLandingContext& context) const {
    if(resolve_richonline_controlled_static_landing(game_id_,context)) return;
    if (context.synthetic_actor) {
        static_cast<void>(resolve_richonline_empty_boss_landing(game_id_,context));
        return;
    }
    if (context.game_mode!=3 || context.actor_slot!=0 || context.position<0 || context.property_ref!=-1 ||
        (context.occupied_by_other_actor && !context.collision_resolved) || context.road_degree==0 || context.road_degree>4 ||
        (context.static_type!=-1 && context.static_type!=5 && context.static_type!=6 && context.static_type!=7))
        throw CodecError("richonline_boss_landing_unsupported");
    // NEW7C54B0 applies80/50/30 locally on5/6/7 after4013, without another ACK.
    const std::uint32_t reward=context.static_type==5 ? 80U : context.static_type==6 ? 50U : context.static_type==7 ? 30U : 0U;
    const auto funds=ledger_->snapshot(0);
    if (funds.funds.tickets>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())-reward)
        throw CodecError("richonline_boss_points_out_of_range");
}
RichonlineLandingResult RichonlineBossLandingState::land(const RichonlineLandingContext& context) {
    validate_landing(context);
    if(auto controlled=resolve_richonline_controlled_static_landing(game_id_,context)) return std::move(*controlled);
    if (context.synthetic_actor) return resolve_richonline_empty_boss_landing(game_id_,context);
    const std::uint32_t reward=context.static_type==5 ? 80U : context.static_type==6 ? 50U : context.static_type==7 ? 30U : 0U;
    const auto funds=ledger_->snapshot(0);
    Bytes packet;
    append_le(packet,0x4013,2); append_le(packet,game_id_,2);
    append_le(packet,static_cast<std::uint16_t>(context.position),2);
    RichonlineLandingResult result{{std::move(packet)},RichonlineLandingProgress::complete};
    ledger_->adjust(0,funds,{0,0,reward,0});
    return result;
}
void RichonlineBossLandingState::commit_points(std::uint8_t actor,std::uint32_t expected,std::uint32_t updated) {
    if (actor>=ledger_->actor_count() || updated>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("richonline_boss_points_out_of_range");
    const auto snapshot=ledger_->snapshot(actor);
    if (snapshot.funds.tickets!=expected) throw CodecError("richonline_boss_points_changed");
    auto funds=snapshot.funds; funds.tickets=updated;
    ledger_->commit(actor,snapshot,funds);
}
RichonlineLandingResult resolve_richonline_empty_boss_landing(std::uint16_t game_server_id,
    const RichonlineLandingContext& context) {
    if (context.game_mode != 3 || !context.synthetic_actor || context.actor_slot >= 8 ||
        context.position < 0 || context.property_ref != -1 || (context.occupied_by_other_actor && !context.collision_resolved) ||
        context.road_degree == 0 || context.road_degree > 4)
        throw CodecError("richonline_boss_landing_unsupported");
    switch (context.static_type) {
    case -1: case 5: case 6: case 7: case 8: case 10: case 41: case 42: break;
    default: throw CodecError("richonline_boss_landing_unsupported");
    }
    Bytes packet;
    append_le(packet,0x4013,2);
    append_le(packet,game_server_id,2);
    append_le(packet,static_cast<std::uint16_t>(context.position),2);
    RichonlineLandingResult result{{std::move(packet)},RichonlineLandingProgress::complete};
    if (context.static_type == 10 && !richonline_landing_controlled(context.actor_status)) {
        // BOSS has no card inventory under the selected game rule. New660B00's
        // signed -1 branch closes shop20 without reading stock or requiring4030.
        Bytes close;
        append_le(close,0x4031,2);
        append_le(close,game_server_id,2);
        close.push_back(0xff);
        result.messages.push_back(std::move(close));
    }
    return result;
}
}
