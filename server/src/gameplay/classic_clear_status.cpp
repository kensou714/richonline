#include "richonline_classic_clear_status.hpp"
#include "lua_wire.hpp"
#include <algorithm>

namespace richnet {
RichonlineClassicClearStatusPlan prepare_richonline_classic_clear_status(View packet,std::uint16_t calendar,
    const RichonlinePlayerCards& cards,std::span<const RichonlineActorStatus> statuses,
    std::span<const std::uint8_t> active,const std::shared_ptr<LuaServer>& script) {
    if(packet.size()!=8 || read_le(packet.first(2))!=135 || read_le(packet.subspan(2,2))!=calendar ||
        packet[4]>=8 || packet[5]!=0)
        throw CodecError("richonline_classic_clear_status_wire_invalid");
    const auto actor=cards.actor_slot(),target=packet[6];
    if(cards.game_mode()!=0 || active.size()<2 || active.size()>4 || statuses.size()!=active.size() ||
        actor>=active.size() || target>=active.size() || !active[actor] || !active[target] ||
        std::ranges::any_of(active,[](auto value){return value>1;}))
        throw CodecError("richonline_classic_clear_status_context_invalid");
    const auto consumed=cards.prepare_consumption(static_cast<std::int8_t>(packet[4]),1078);
    if(!consumed) throw CodecError("richonline_classic_clear_status_not_owned");
    RichonlineClassicClearStatusPlan plan;
    plan.cards_=&cards;plan.target_=target;
    plan.inventory_before_=consumed->source_inventory;plan.inventory_after_=consumed->remaining_inventory;
    plan.statuses_before_.assign(statuses.begin(),statuses.end());plan.active_before_.assign(active.begin(),active.end());
    auto& after=plan.target_after_;after=statuses[target];
    if(!after.possession) throw CodecError("richonline_classic_clear_status_possession_unknown");
    // 6748A0有附身/炸弹才排6050/6065；不对已无附身的角色额外改强度字段。
    if(*after.possession!=-1) {
        richonline_detach_possession(after);
        after.possession=-1; // 经典会话用显式-1表示已知无附身，nullopt是未知。
    }
    after.timed_bomb.reset();after.timed_bomb_owner.reset();
    // 606F→7F9560只清这六个计时；保留1696免疫、攻击/伤害倍率及其他独立字段。
    after.stay=after.turtle=after.sleepwalking=after.frozen=after.one_step=after.six_steps=0;
    append_le(plan.response_,0x40d7,2);append_le(plan.response_,cards.game_id(),2);
    plan.response_.insert(plan.response_.end(),{packet[4],0,target,0});
    if(script) {
        bool snapshot_read=false,consumed_call=false,status_call=false,relations_call=false,invalid=false;
        const auto reject=[&]() -> LuaValue {
            invalid=true;throw CodecError("lua_classic_clear_status_plan_invalid");
        };
        const LuaBindings bindings{
            {"game.snapshot",[&](const LuaValue&) {
                if(snapshot_read) return reject();
                snapshot_read=true;auto actors=LuaValue::array();
                for(const auto present:active) actors.push_back({{"active",present!=0}});
                return LuaValue{{"mode",0},{"actors",std::move(actors)}};
            }},
            {"card.prepare",[&](const LuaValue& args) {
                if(!snapshot_read || consumed_call || args!=LuaValue{{"card",1078}} ||
                    !args.at("card").is_number_integer()) return reject();
                consumed_call=true;return LuaValue{{"slot",packet[4]},{"bank",0}};
            }},
            {"status.prepare_clear",[&](const LuaValue& args) {
                const LuaValue fields=LuaValue::array({"possession","timed_bomb","sleepwalking","turtle",
                    "stay","one_step","six_steps","frozen"});
                if(!consumed_call || status_call || args!=LuaValue{{"target",target},{"fields",fields}} ||
                    !args.at("target").is_number_integer()) return reject();
                status_call=true;return LuaValue{};
            }},
            {"relations.clear_actor",[&](const LuaValue& args) {
                // 与现有经典资金卡相同：关系保持开局全零；未来结盟接入必须扩展事务。
                if(!status_call || relations_call || args!=LuaValue{{"target",target}} ||
                    !args.at("target").is_number_integer()) return reject();
                relations_call=true;return LuaValue{};
            }}
        };
        const auto result=script->call("game.action",{{"payload",lua_bytes(packet)},{"opcode",135},{"mode",0},
            {"map",std::string(cards.map_name())},{"actor",actor},{"calendar",calendar},{"game_id",cards.game_id()}},bindings);
        if(invalid || !snapshot_read || !consumed_call || !status_call || !relations_call ||
            !result.is_array() || result.size()!=1 || !result[0].is_string() || lua_bytes(result[0])!=plan.response_)
            throw CodecError("lua_classic_clear_status_response_invalid");
    }
    return plan;
}
bool commit_richonline_classic_clear_status(RichonlinePlayerCards& cards,
    std::span<RichonlineActorStatus> statuses,std::span<const std::uint8_t> active,
    const RichonlineClassicClearStatusPlan& plan) noexcept {
    if(&cards!=plan.cards_ || cards.inventory()!=plan.inventory_before_ ||
        !std::ranges::equal(statuses,plan.statuses_before_) || !std::ranges::equal(active,plan.active_before_)) return false;
    cards.commit_inventory(plan.inventory_after_);statuses[plan.target_]=plan.target_after_;
    return true;
}
}
