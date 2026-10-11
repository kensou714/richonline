#include "richonline_classic_property_card.hpp"
#include "lua_wire.hpp"
#include <algorithm>
#include <bit>

namespace richnet {
RichonlineClassicPropertyCardPlan prepare_richonline_classic_property_card(View packet,std::uint16_t calendar,
    std::int16_t current_property,std::int32_t land_equipment,const RichonlinePlayerCards& cards,
    const RichonlineClassicProperty& property,const RichonlineGameLedger& ledger,
    std::span<const std::uint8_t> active,const std::shared_ptr<LuaServer>& script) {
    if(packet.size()<6) throw CodecError("richonline_classic_property_card_wire_invalid");
    const auto opcode=read_le(packet.first(2));
    const bool has_target=opcode==97 || opcode==98 || opcode==101;
    if((opcode!=96 && opcode!=97 && opcode!=98 && opcode!=100 && opcode!=101 && opcode!=102) ||
        packet.size()!=(has_target?8U:6U) || read_le(packet.subspan(2,2))!=calendar || packet[4]>=8 || packet[5]!=0)
        throw CodecError("richonline_classic_property_card_wire_invalid");
    const auto actor=cards.actor_slot();
    if(cards.game_mode()!=0 || property.game_id()!=cards.game_id() || !property.uses_ledger(ledger) ||
        active.size()<2 || active.size()>4 || active.size()!=ledger.actor_count() || actor>=active.size() ||
        !active[actor] || std::ranges::any_of(active,[](auto value){return value>1;}))
        throw CodecError("richonline_classic_property_card_context_invalid");
    const auto card_id=static_cast<std::int16_t>(opcode+935);
    const auto consumed=cards.prepare_consumption(static_cast<std::int8_t>(packet[4]),card_id);
    if(!consumed) throw CodecError("richonline_classic_property_card_not_owned");
    const auto target=has_target ? std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(read_le(packet.subspan(6,2)))) :
        current_property;
    RichonlineClassicPropertyCardPlan plan;
    plan.cards_=&cards;plan.ledger_=&ledger;plan.property_=&property;
    plan.before_inventory_=consumed->source_inventory;plan.after_inventory_=consumed->remaining_inventory;
    plan.active_.assign(active.begin(),active.end());
    LuaValue operation;
    std::uint32_t price=0;
    if(opcode==96) {
        plan.change_=property.prepare_card_purchase(current_property,actor);
        // 7CF5E0/63F3C0：P+152大于0则地价右移一位；不叠加神明折扣或建筑价格。
        price=plan.change_->before()[0].price;
        if(land_equipment>0) price/=2;
        const auto before=ledger.snapshot(actor);
        if(before.funds.cash<=price) throw CodecError("richonline_classic_purchase_card_cash_insufficient");
        auto after=before.funds;after.cash-=price;
        plan.funds_=RichonlineGameFundsUpdate{actor,before,after};
        operation={{"operation","purchase"}};
    } else if(opcode==100) {
        plan.change_=property.prepare_card_seal(current_property);
        operation={{"operation","seal"}};
    } else if(opcode==97 || opcode==98) {
        plan.change_=property.prepare_card_swap(current_property,target,opcode==98);
        operation={{"operation","swap"},{"property",target},{"buildings",opcode==98}};
    } else {
        plan.change_=property.prepare_card_destruction(target,opcode==101?1:5);
        operation={{"operation","destroy"},{"current",opcode==102},{"levels",opcode==101?1:5}};
        if(opcode==101) operation["property"]=target;
    }
    append_le(plan.response_,opcode+0x4050,2);append_le(plan.response_,cards.game_id(),2);
    plan.response_.insert(plan.response_.end(),packet.begin()+4,packet.end());
    if(script) {
        bool consumed_call=false,property_call=false,snapshot_call=false,funds_call=false,invalid=false;
        const auto reject=[&]() -> LuaValue {
            invalid=true;throw CodecError("lua_classic_property_card_plan_invalid");
        };
        const LuaBindings bindings{
            {"card.prepare",[&](const LuaValue& args) {
                if(consumed_call || args!=LuaValue{{"card",card_id}} || !args.at("card").is_number_integer())
                    return reject();
                consumed_call=true;return LuaValue{{"slot",packet[4]},{"bank",0}};
            }},
            {"property.prepare",[&](const LuaValue& args) {
                if(!consumed_call || property_call || args!=operation) return reject();
                // JSON数值相等仍可能是浮点；Lua业务参数须保持原整数/布尔/字符串类型。
                for(auto it=args.begin();it!=args.end();++it) {
                    if((it.key()=="property" || it.key()=="levels") && !it->is_number_integer()) return reject();
                    if((it.key()=="buildings" || it.key()=="current") && !it->is_boolean()) return reject();
                }
                property_call=true;return LuaValue{{"price",price}};
            }},
            {"game.snapshot",[&](const LuaValue&) {
                if(opcode!=96 || !property_call || snapshot_call) return reject();
                snapshot_call=true;auto actors=LuaValue::array();
                // 购地模块只读施放者现金，其余槽不提供虚构余额。
                for(std::size_t slot=0;slot<active.size();++slot)
                    actors.push_back(slot==actor ? LuaValue{{"cash",plan.funds_->before.funds.cash}} : LuaValue::object());
                return LuaValue{{"mode",0},{"actors",std::move(actors)}};
            }},
            {"funds.prepare",[&](const LuaValue& args) {
                if(opcode!=96 || !snapshot_call || funds_call ||
                    args!=LuaValue{{"actor",actor},{"cash",-static_cast<std::int64_t>(price)}} ||
                    !std::ranges::all_of(args,[](const auto& value){return value.is_number_integer();})) return reject();
                funds_call=true;return LuaValue{};
            }}
        };
        const auto response=script->call("game.action",{{"payload",lua_bytes(packet)},{"opcode",opcode},
            {"map",std::string(cards.map_name())},{"actor",actor},{"calendar",calendar},
            {"game_id",cards.game_id()}},bindings);
        if(invalid || !consumed_call || !property_call || snapshot_call!=(opcode==96) || funds_call!=(opcode==96) ||
            !response.is_array() || response.size()!=1 || !response[0].is_string() || lua_bytes(response[0])!=plan.response_)
            throw CodecError("lua_classic_property_card_response_invalid");
    }
    return plan;
}
bool commit_richonline_classic_property_card(RichonlinePlayerCards& cards,RichonlineClassicProperty& property,
    RichonlineGameLedger& ledger,std::span<const std::uint8_t> active,const RichonlineClassicPropertyCardPlan& plan) {
    const auto ready=[&]() noexcept {
        return &cards==plan.cards_ && &ledger==plan.ledger_ && &property==plan.property_ && plan.change_ &&
            cards.inventory()==plan.before_inventory_ && std::ranges::equal(active,plan.active_) &&
            property.matches(*plan.change_);
    };
    if(!ready()) return false;
    const auto commit=[&]() noexcept {
        if(!ready() || !property.commit_card_change(*plan.change_)) return false;
        cards.commit_inventory(plan.after_inventory_);return true;
    };
    if(plan.funds_) return ledger.commit_batch(std::span{&*plan.funds_,1},commit);
    return commit();
}
}
