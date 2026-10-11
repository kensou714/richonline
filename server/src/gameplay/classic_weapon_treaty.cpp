#include "richonline_classic_weapon_treaty.hpp"
#include "lua_wire.hpp"
#include <algorithm>

namespace richnet {
RichonlineClassicWeaponTreatyPlan prepare_richonline_classic_weapon_treaty(View packet,
    std::uint16_t calendar,std::uint8_t actor,std::span<const std::shared_ptr<RichonlinePlayerCards>> owners,
    std::span<const std::uint8_t> active,const std::shared_ptr<LuaServer>& script) {
    if(packet.size()!=6 || read_le(packet.first(2))!=142 ||
        read_le(packet.subspan(2,2))!=calendar || packet[4]>=8 || packet[5]!=0)
        throw CodecError("richonline_classic_weapon_treaty_wire_invalid");
    if(owners.size()<2 || owners.size()>4 || active.size()!=owners.size() || actor>=owners.size() ||
        !active[actor] || std::ranges::any_of(active,[](auto value){return value>1;}) || !owners[actor])
        throw CodecError("richonline_classic_weapon_treaty_context_invalid");
    const auto& source=*owners[actor];
    for(std::size_t slot=0;slot<owners.size();++slot) {
        if(!owners[slot] || owners[slot]->actor_slot()!=slot || owners[slot]->game_mode()!=0 ||
            owners[slot]->game_id()!=source.game_id() || owners[slot]->map_name()!=source.map_name())
            throw CodecError("richonline_classic_weapon_treaty_owner_invalid");
    }
    const auto consumed=source.prepare_consumption(static_cast<std::int8_t>(packet[4]),1115);
    if(!consumed) throw CodecError("richonline_classic_weapon_treaty_not_owned");
    RichonlineClassicWeaponTreatyPlan plan;
    plan.owners_.assign(owners.begin(),owners.end());
    plan.active_.assign(active.begin(),active.end());
    for(const auto& owner:owners) plan.before_.push_back(owner->inventory());
    plan.after_=plan.before_;
    plan.after_[actor]=consumed->remaining_inventory;
    constexpr std::array<std::int16_t,5> weapons{1044,1045,1046,1063,1075};
    for(std::size_t actor_slot=0;actor_slot<owners.size();++actor_slot) if(active[actor_slot]) {
        // 680310只检查活动标志；收容、冰冻或梦游的活动玩家也受影响。
        // 7F8FF0清除整叠并保留原槽位置，不压缩、不合成，也不触碰第二套手牌。
        for(auto& slot:plan.after_[actor_slot])
            if(std::ranges::find(weapons,slot.card_id)!=weapons.end()) slot={};
    }
    append_le(plan.response_,0x40de,2);append_le(plan.response_,source.game_id(),2);
    plan.response_.insert(plan.response_.end(),{packet[4],0});
    if(script) {
        bool consumed_call=false,cleared_call=false,invalid=false;
        const auto reject=[&]() -> LuaValue {
            invalid=true;throw CodecError("lua_classic_weapon_treaty_plan_invalid");
        };
        const LuaBindings bindings{
            {"card.prepare",[&](const LuaValue& args) {
                if(consumed_call || args!=LuaValue{{"card",1115}} || !args.at("card").is_number_integer())
                    return reject();
                consumed_call=true;return LuaValue{{"slot",packet[4]},{"bank",0}};
            }},
            {"inventory.prepare_clear",[&](const LuaValue& args) {
                const LuaValue expected{{"cards",weapons}};
                if(!consumed_call || cleared_call || args!=expected ||
                    !std::ranges::all_of(args.at("cards"),[](const auto& value){return value.is_number_integer();}))
                    return reject();
                cleared_call=true;return LuaValue{};
            }}
        };
        const auto response=script->call("game.action",{{"payload",lua_bytes(packet)},{"opcode",142},
            {"map",std::string(source.map_name())},{"actor",actor},{"calendar",calendar},
            {"game_id",source.game_id()}},bindings);
        if(invalid || !consumed_call || !cleared_call || !response.is_array() || response.size()!=1 ||
            !response[0].is_string() || lua_bytes(response[0])!=plan.response_)
            throw CodecError("lua_classic_weapon_treaty_response_invalid");
    }
    return plan;
}
bool commit_richonline_classic_weapon_treaty(std::span<const std::shared_ptr<RichonlinePlayerCards>> owners,
    std::span<const std::uint8_t> active,const RichonlineClassicWeaponTreatyPlan& plan) {
    if(!std::ranges::equal(owners,plan.owners_) || !std::ranges::equal(active,plan.active_) ||
        owners.size()!=plan.before_.size() || owners.size()!=plan.after_.size()) return false;
    for(std::size_t slot=0;slot<owners.size();++slot)
        if(!owners[slot] || owners[slot]->inventory()!=plan.before_[slot]) return false;
    for(std::size_t slot=0;slot<owners.size();++slot)
        if(active[slot]) owners[slot]->commit_inventory(plan.after_[slot]);
    return true;
}
}
