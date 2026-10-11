#include "richonline_classic_alliance.hpp"
#include "lua_wire.hpp"
#include <algorithm>

namespace richnet {
void break_richonline_classic_alliance(RichonlineClassicAlliances& relations,
    std::uint8_t source,std::uint8_t target) noexcept {
    if(source<8 && target<8 && static_cast<std::int8_t>(relations[source][target])>0)
        relations[source][target]=relations[target][source]=0;
}
void clear_richonline_classic_alliances(RichonlineClassicAlliances& relations,std::uint8_t actor) noexcept {
    for(std::uint8_t target=0;target<8;++target) break_richonline_classic_alliance(relations,actor,target);
}
RichonlineClassicAlliancePlan prepare_richonline_classic_alliance(View packet,std::uint16_t calendar,
    std::uint8_t days,const RichonlinePlayerCards& cards,std::span<const std::uint8_t> active,
    const RichonlineClassicAlliances& relations,const std::shared_ptr<LuaServer>& script) {
    if(packet.size()!=8 || read_le(packet.first(2))!=121 || read_le(packet.subspan(2,2))!=calendar ||
        packet[4]>=8 || packet[5]!=0) throw CodecError("richonline_classic_alliance_wire_invalid");
    const auto actor=cards.actor_slot(),target=packet[6];
    if(cards.game_mode()!=0 || active.size()<2 || active.size()>4 || actor>=active.size() ||
        target>=active.size() || target==actor || !active[actor] || !active[target] || !days || days>127 ||
        std::ranges::any_of(active,[](auto value){return value>1;}))
        throw CodecError("richonline_classic_alliance_context_invalid");
    const auto consumption=cards.prepare_consumption(static_cast<std::int8_t>(packet[4]),1060);
    if(!consumption) throw CodecError("richonline_classic_alliance_not_owned");
    RichonlineClassicAlliancePlan plan;
    plan.cards_=&cards;plan.inventory_before_=consumption->source_inventory;
    plan.inventory_after_=consumption->remaining_inventory;plan.before_=plan.after_=relations;
    plan.after_[actor][target]=plan.after_[target][actor]=days;
    plan.active_.assign(active.begin(),active.end());
    append_le(plan.response_,0x40c9,2);append_le(plan.response_,cards.game_id(),2);
    plan.response_.insert(plan.response_.end(),{packet[4],0,target,0});
    if(script) {
        unsigned step=0;bool invalid=false;
        const auto reject=[&]() -> LuaValue {invalid=true;throw CodecError("lua_classic_alliance_plan_invalid");};
        const LuaBindings bindings{
            {"game.snapshot",[&](const LuaValue&) {
                if(step!=0) return reject();
                ++step;
                auto actors=LuaValue::array();
                for(const auto present:active) actors.push_back({{"active",present!=0}});
                return LuaValue{{"actors",std::move(actors)},{"mode",0}};
            }},
            {"card.prepare",[&](const LuaValue& args) {
                if(step!=1 || args!=LuaValue{{"card",1060}} || !args.at("card").is_number_integer()) return reject();
                ++step;return LuaValue{{"slot",packet[4]},{"bank",0}};
            }},
            {"relations.rules",[&](const LuaValue&) {
                if(step!=2) return reject();
                ++step;return LuaValue{{"alliance_days",days}};
            }},
            {"relations.prepare",[&](const LuaValue& args) {
                if(step!=3 || args!=LuaValue{{"target",target},{"days",days}} ||
                    !args.at("target").is_number_integer() || !args.at("days").is_number_integer()) return reject();
                ++step;return LuaValue{};
            }}
        };
        const auto result=script->call("game.action",{{"payload",lua_bytes(packet)},{"opcode",121},{"mode",0},
            {"map",std::string(cards.map_name())},{"actor",actor},{"calendar",calendar},{"game_id",cards.game_id()}},bindings);
        if(invalid || step!=4 || !result.is_array() || result.size()!=1 || !result[0].is_string() ||
            lua_bytes(result[0])!=plan.response_) throw CodecError("lua_classic_alliance_response_invalid");
    }
    return plan;
}
bool commit_richonline_classic_alliance(RichonlinePlayerCards& cards,std::span<const std::uint8_t> active,
    RichonlineClassicAlliances& relations,const RichonlineClassicAlliancePlan& plan) noexcept {
    if(&cards!=plan.cards_ || cards.inventory()!=plan.inventory_before_ || relations!=plan.before_ ||
        !std::ranges::equal(active,plan.active_)) return false;
    cards.commit_inventory(plan.inventory_after_);relations=plan.after_;return true;
}
}
