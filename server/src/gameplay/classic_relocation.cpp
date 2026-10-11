#include "richonline_classic_relocation.hpp"
#include "lua_wire.hpp"
#include <algorithm>

namespace richnet {
namespace {
bool available(const RichonlineClassicRelocationActor& actor) {
    return actor.active && actor.raw.hotel1493==-1 && actor.raw.hospital1494==-1 &&
        actor.raw.jail1495==-1 && actor.raw.kidnapped1497==-1;
}
}
RichonlineClassicRelocationPlan prepare_richonline_classic_swap_positions(View packet,std::uint16_t calendar,
    const RichonlinePlayerCards& cards,const RichonlineRoadTopology& topology,
    std::span<const RichonlineClassicRelocationActor> actors,const std::shared_ptr<LuaServer>& script) {
    if(packet.size()!=6 || read_le(packet.first(2))!=161 || read_le(packet.subspan(2,2))!=calendar ||
        packet[4]>=8 || packet[5]!=0)
        throw CodecError("richonline_classic_swap_positions_wire_invalid");
    const auto source=cards.actor_slot();
    if(cards.game_mode()!=0 || actors.size()<2 || actors.size()>4 || source>=actors.size() ||
        !available(actors[source]) || actors[source].status.frozen)
        throw CodecError("richonline_classic_swap_positions_context_invalid");
    const auto consumed=cards.prepare_consumption(static_cast<std::int8_t>(packet[4]),503);
    if(!consumed) throw CodecError("richonline_classic_swap_positions_not_owned");
    RichonlineClassicRelocationPlan plan;
    plan.cards_=&cards;plan.inventory_before_=consumed->source_inventory;plan.inventory_after_=consumed->remaining_inventory;
    plan.before_.assign(actors.begin(),actors.end());
    std::vector<std::uint8_t> eligible;
    for(std::uint8_t slot=0;slot<actors.size();++slot) {
        const auto& person=actors[slot];plan.positions_.push_back(person.position);
        if(!person.active) continue;
        if(!person.raw.hotel1493 || !person.raw.hospital1494 || !person.raw.jail1495 || !person.raw.kidnapped1497)
            throw CodecError("richonline_classic_swap_positions_raw_unknown");
        if(available(person) && !person.status.frozen) {
            if(person.heading>3 || !topology.cell(person.position).walkable)
                throw CodecError("richonline_classic_swap_positions_geometry_invalid");
            eligible.push_back(slot);
        }
    }
    if(eligible.size()<2) throw CodecError("richonline_classic_swap_positions_participants_insufficient");
    // 7CF170先快照所有合格位置，再按槽号寻找下一位；不能边写边读导致最后一人错位。
    for(std::size_t index=0;index<eligible.size();++index)
        plan.positions_[eligible[index]]=actors[eligible[(index+1)%eligible.size()]].position;
    append_le(plan.response_,0x40f1,2);append_le(plan.response_,cards.game_id(),2);
    plan.response_.insert(plan.response_.end(),{packet[4],0});
    if(script) {
        bool consumed_call=false,snapshot_call=false,positions_call=false,invalid=false;
        const auto reject=[&]() -> LuaValue {
            invalid=true;throw CodecError("lua_classic_swap_positions_plan_invalid");
        };
        const LuaBindings bindings{
            {"card.prepare",[&](const LuaValue& args) {
                if(consumed_call || args!=LuaValue{{"card",503}} || !args.at("card").is_number_integer()) return reject();
                consumed_call=true;return LuaValue{{"slot",packet[4]},{"bank",0}};
            }},
            {"actor.relocation_snapshot",[&](const LuaValue&) {
                if(!consumed_call || snapshot_call) return reject();
                snapshot_call=true;auto result=LuaValue::array();
                for(std::uint8_t slot=0;slot<actors.size();++slot)
                    result.push_back({{"slot",slot},{"position",actors[slot].position},{"active",actors[slot].active},
                        {"raw_available",available(actors[slot])},{"frozen",actors[slot].status.frozen!=0}});
                return result;
            }},
            {"actor.prepare_positions",[&](const LuaValue& args) {
                if(!snapshot_call || positions_call) return reject();
                auto expected=LuaValue::array();
                for(const auto slot:eligible) expected.push_back({{"actor",slot},{"position",plan.positions_[slot]}});
                if(args!=LuaValue{{"positions",expected}}) return reject();
                for(const auto& entry:args.at("positions"))
                    if(!entry.at("actor").is_number_integer() || !entry.at("position").is_number_integer()) return reject();
                positions_call=true;return LuaValue{};
            }}
        };
        const auto result=script->call("game.action",{{"payload",lua_bytes(packet)},{"opcode",161},{"mode",0},
            {"map",std::string(cards.map_name())},{"actor",source},{"calendar",calendar},{"game_id",cards.game_id()}},bindings);
        if(invalid || !consumed_call || !snapshot_call || !positions_call || !result.is_array() ||
            result.size()!=1 || !result[0].is_string() || lua_bytes(result[0])!=plan.response_)
            throw CodecError("lua_classic_swap_positions_response_invalid");
    }
    return plan;
}
bool matches_richonline_classic_relocation(const RichonlinePlayerCards& cards,
    std::span<const RichonlineClassicRelocationActor> current,const RichonlineClassicRelocationPlan& plan) noexcept {
    return &cards==plan.cards_ && cards.inventory()==plan.inventory_before_ && std::ranges::equal(current,plan.before_);
}
bool commit_richonline_classic_relocation(RichonlinePlayerCards& cards,std::span<RichonlineBoardParticipant> participants,
    std::span<const RichonlineClassicRelocationActor> current,const RichonlineClassicRelocationPlan& plan) noexcept {
    if(!matches_richonline_classic_relocation(cards,current,plan) || participants.size()!=plan.before_.size()) return false;
    for(std::size_t slot=0;slot<participants.size();++slot)
        if(participants[slot].position!=current[slot].position || participants[slot].direction!=current[slot].heading)
            return false;
    cards.commit_inventory(plan.inventory_after_);
    for(std::size_t slot=0;slot<participants.size();++slot) participants[slot].position=plan.positions_[slot];
    return true;
}
}
