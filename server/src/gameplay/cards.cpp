#include "richonline_boss_cards.hpp"
#include "richonline_fixed_step_card.hpp"
#include "richonline_cosmetic_card.hpp"
#include "richonline_shop_catalog.hpp"

#include <utility>
#include <string_view>
#include <algorithm>
#include <set>

namespace richnet {
namespace {
std::optional<std::int16_t> fixed_tile_reward(std::int8_t type) noexcept {
    // Texture names identify these item families. The exact original server
    // lottery is unknown; native policy awards one matching usable card.
    switch(type) {
    case 41: return 1044;
    case 42: return 1046;
    case 43: return 1045;
    case 51: return 1182;
    case 53: return 1183;
    case 54: return 1038;
    default: return {};
    }
}
RichonlineChanceSingleCard checked_award(const std::shared_ptr<const RichonlineChanceResources>& resources,
    const RichonlineBossCardPolicy& policy) {
    if (!resources) throw CodecError("richonline_boss_card_resources_required");
    return resources->single_card(policy.map_name,policy.event_id,policy.card_id);
}
}
bool richonline_boss_card_reward_tile(std::int8_t static_type) noexcept {
    return static_type==8 || fixed_tile_reward(static_type).has_value();
}
RichonlineBossCards::RichonlineBossCards(std::shared_ptr<const RichonlineChanceResources> resources,
    std::uint16_t game_id,const RichonlineBossCardPolicy& policy)
    : resources_(std::move(resources)), award_(checked_award(resources_,policy)),
      game_id_(game_id), opaque6_7_(policy.opaque6_7) {}

void RichonlineBossCards::configure_tile_rewards(std::vector<std::int16_t> playable,RichonlineRouteChooser random,
    const RichonlineShopCatalog& resale) {
    // 共享池统一服务卡片格、福神、新闻、节日；脚本返回也必须通过商店实际出售能力校验。
    std::erase_if(playable,[&](const auto card){return !resale.can_sell(card);});
    configure_tile_rewards(std::move(playable),std::move(random));
}
void RichonlineBossCards::configure_tile_rewards(std::vector<std::int16_t> playable,RichonlineRouteChooser random) {
    if(!random) throw CodecError("richonline_card_tile_random_required");
    std::set<std::int16_t> unique;
    std::vector<std::int16_t> candidates;
    for(const auto card:playable) {
        if(card<=0||!unique.insert(card).second) throw CodecError("richonline_card_tile_policy_invalid");
        // 随机奖励禁止商城金豆卡和星光环绕；Lua 缺席或候选配置误放时也不能重新混入。
        if((card>=500 && card<=519) || card==1131) continue;
        if(resources_->contains_card(card)&&resources_->automatic_card_eligible(award_.map(),card))
            candidates.push_back(card);
    }
    if(candidates.empty()) throw CodecError("richonline_card_tile_pool_empty");
    tile_reward_cards_=std::move(candidates);
    tile_random_=std::move(random);
}

std::optional<RichonlineLandingResult> RichonlineBossCards::land(const RichonlineLandingContext& context) {
    if (context.actor_slot != 0 || context.game_mode != 3 || context.synthetic_actor ||
        (context.static_type != 68 && !richonline_boss_card_reward_tile(context.static_type)) ||
        context.property_ref != -1 || context.road_degree == 0 || context.road_degree > 4 ||
        (context.occupied_by_other_actor && !context.collision_resolved) || context.position < 0) return {};
    auto next = inventory_;
    auto card = fixed_tile_reward(context.static_type).value_or(award_.card_id());
    if(fixed_tile_reward(context.static_type) && !resources_->automatic_card_eligible(award_.map(),card))
        throw CodecError("richonline_card_tile_reward_not_eligible");
    if(context.static_type==8) {
        const auto reward=prepare_random_reward();
        card=reward.card;
        next=reward.inventory;
    }
    try { if(context.static_type!=8) next = context.static_type == 68 ? resources_->insert(award_,inventory_) : prepare_add(card); }
    catch (const CodecError& error) {
        if (std::string_view(error.what()) != "richonline_chance_inventory_full") throw;
    }
    Bytes stop;
    append_le(stop,0x4013,2); append_le(stop,game_id_,2); append_le(stop,static_cast<std::uint16_t>(context.position),2);
    Bytes reward;
    if (context.static_type != 68) {
        append_le(reward,0x4029,2);
        append_le(reward,game_id_,2);
        append_le(reward,static_cast<std::uint16_t>(card),2);
    } else reward = encode_richonline_chance_single_card(game_id_,award_,opaque6_7_);
    std::optional<RichonlineLandingResult> result{RichonlineLandingResult{
        {std::move(stop),std::move(reward)},RichonlineLandingProgress::complete}};
    inventory_ = next;
    return result;
}
RichonlineChanceInventory RichonlineBossCards::prepare_reward() const {
    return resources_->insert(award_,inventory_);
}
RichonlineChanceInventory RichonlineBossCards::prepare_add(std::int16_t card_id,std::int16_t count) const {
    return resources_->add(award_.map(),card_id,count,inventory_);
}
RichonlineBossCards::PreparedReward RichonlineBossCards::prepare_random_reward() const {
    return prepare_random_reward(inventory_);
}
RichonlineBossCards::PreparedReward RichonlineBossCards::prepare_random_reward(const RichonlineChanceInventory& source) const {
    if(!tile_random_||tile_reward_cards_.empty()) throw CodecError("richonline_card_tile_policy_required");
    std::vector<PreparedReward> candidates;
    for(const auto card:tile_reward_cards_) {
        auto resulting=source;
        try { resulting=resources_->add(award_.map(),card,1,source); }
        catch(const CodecError& error) {
            // NEW7F8780 leaves a full hand unchanged and still continues the event.
            if(std::string_view(error.what())!="richonline_chance_inventory_full") throw;
        }
        // 合成产物由 CombCard 与客户端插入顺序决定，不应反过来改变抽卡概率。
        candidates.push_back({card,resulting});
    }
    if(candidates.empty()) throw CodecError("richonline_card_tile_no_safe_reward");
    const auto selected=tile_random_(candidates.size());
    if(selected>=candidates.size()) throw CodecError("richonline_card_tile_random_invalid");
    return candidates[selected];
}
RichonlineBossCards::PreparedDiscard RichonlineBossCards::prepare_discard(
    const RichonlineCardDiscardRequest50& request,std::int8_t actor) const {
    return {encode_richonline_card_discard4033(game_id_,request.inventory_slot,actor),
        resources_->discard(inventory_,request.inventory_slot)};
}
std::optional<RichonlineBossCards::PendingTargetEffect> RichonlineBossCards::prepare_target_effect(
    const RichonlineTargetCardRequest& request) const {
    if (request.inventory_slot<0 || request.inventory_slot>=8 || request.inventory_bank!=0 || request.target<0)
        throw CodecError("richonline_target_card_request_invalid");
    const auto card = request.kind == RichonlineTargetCard::mine1044 ? 1044 :
        request.kind == RichonlineTargetCard::missile1046 ? 1046 :
        request.kind == RichonlineTargetCard::nuclear1063 ? 1063 :
        request.kind == RichonlineTargetCard::safe_nuclear1075 ? 1075 : -1;
    if (card<0) throw CodecError("richonline_target_card_kind_invalid");
    const auto slot = static_cast<std::size_t>(request.inventory_slot);
    if (inventory_[slot].card_id != card || inventory_[slot].count<=0) return {};
    auto remaining=inventory_;
    if (--remaining[slot].count==0) remaining[slot]={};
    return PendingTargetEffect{request,inventory_,remaining};
}
void RichonlineBossCards::commit_target_effect(const PendingTargetEffect& pending) {
    if (inventory_ != pending.source_inventory) throw CodecError("richonline_target_card_inventory_changed");
    inventory_=pending.remaining_inventory;
}
std::optional<RichonlineBossCards::PreparedConsumption> RichonlineBossCards::prepare_consumption(
    std::int8_t slot,std::int16_t card_id) const {
    if (slot<0 || slot>=8 || !resources_->contains_card(card_id)) throw CodecError("richonline_card_consumption_invalid");
    const auto index=static_cast<std::size_t>(slot);
    if(inventory_[index].card_id!=card_id || inventory_[index].count<=0) return {};
    auto remaining=inventory_;
    if(--remaining[index].count==0) remaining[index]={};
    return PreparedConsumption{inventory_,remaining,slot,card_id};
}
void RichonlineBossCards::commit_consumption(const PreparedConsumption& prepared) {
    if(inventory_!=prepared.source_inventory) throw CodecError("richonline_card_consumption_inventory_changed");
    inventory_=prepared.remaining_inventory;
}
RichonlineBossCards::PreparedShuffle RichonlineBossCards::prepare_shuffle(
    std::int8_t slot,std::uint8_t actor,const RichonlineRouteChooser& random) const {
    if(actor!=0 || !random) throw CodecError("richonline_shuffle_card_context_invalid");
    const auto consumed=prepare_consumption(slot,1125);
    if(!consumed) throw CodecError("richonline_shuffle_card_not_owned");
    std::vector<std::uint8_t> order;
    for(std::uint8_t index=0;index<consumed->remaining_inventory.size();++index) {
        const auto& entry=consumed->remaining_inventory[index];
        if(entry.card_id==-1 && entry.count==0) continue;
        if(!resources_->contains_card(entry.card_id) || entry.count<=0 || entry.count>127)
            throw CodecError("richonline_shuffle_card_inventory_invalid");
        order.push_back(index);
    }
    // Native policy shuffles the existing stacks without generating replacements.
    for(auto size=order.size();size>1;--size) {
        const auto selected=random(size);
        if(selected>=size) throw CodecError("richonline_shuffle_card_random_invalid");
        std::swap(order[size-1],order[selected]);
    }
    return prepare_shuffle_order(slot,actor,order);
}
RichonlineBossCards::PreparedShuffle RichonlineBossCards::prepare_shuffle_order(
    std::int8_t slot,std::uint8_t actor,const std::vector<std::uint8_t>& order) const {
    if(actor!=0) throw CodecError("richonline_shuffle_card_context_invalid");
    const auto consumed=prepare_consumption(slot,1125);
    if(!consumed) throw CodecError("richonline_shuffle_card_not_owned");
    std::array<bool,8> seen{};
    for(const auto index:order) {
        if(index>=seen.size() || seen[index]) throw CodecError("richonline_shuffle_card_order_invalid");
        const auto& entry=consumed->remaining_inventory[index];
        if(!resources_->contains_card(entry.card_id) || entry.count<=0 || entry.count>127)
            throw CodecError("richonline_shuffle_card_inventory_invalid");
        seen[index]=true;
    }
    for(std::size_t index=0;index<seen.size();++index) {
        const auto& entry=consumed->remaining_inventory[index];
        if(!seen[index] && (entry.card_id!=-1 || entry.count!=0))
            throw CodecError("richonline_shuffle_card_order_incomplete");
    }
    PreparedShuffle result{consumed->source_inventory,{}, {}};
    auto& packet=result.confirmation40e8;
    append_le(packet,0x40e8,2);append_le(packet,game_id_,2);
    packet.push_back(static_cast<std::uint8_t>(slot));packet.push_back(0);
    packet.push_back(static_cast<std::uint8_t>(order.size()));packet.push_back(0);
    for(const auto index:order) {
        const auto& entry=consumed->remaining_inventory[index];
        append_le(packet,static_cast<std::uint16_t>(entry.card_id),2);
        packet.push_back(static_cast<std::uint8_t>(entry.count));packet.push_back(actor);
        // NEW607B inserts each wire entry through7F8780/800FD0, including combinations.
        result.remaining_inventory=resources_->add(award_.map(),entry.card_id,entry.count,result.remaining_inventory);
    }
    return result;
}
void RichonlineBossCards::commit_inventory(const RichonlineChanceInventory& inventory) noexcept {
    inventory_ = inventory;
}
std::optional<RichonlineBossCards::PreparedUse> RichonlineBossCards::prepare_use(const RichonlineCardDiceRequest103& request) const {
    if (request.inventory_slot < 0 || request.inventory_slot >= 8 || request.inventory_bank != 0 ||
        request.selected_die < 1 || request.selected_die > 6) throw CodecError("richonline_boss_card_request_invalid");
    const auto slot = static_cast<std::size_t>(request.inventory_slot);
    if (inventory_[slot].card_id != 1038 || inventory_[slot].count <= 0) return {};
    auto remaining = inventory_;
    if (--remaining[slot].count==0) remaining[slot] = {};
    return PreparedUse{encode_richonline_card_used40b7({game_id_,request.inventory_slot,request.inventory_bank}),remaining,request.selected_die};
}
void RichonlineBossCards::commit_use(const PreparedUse& prepared) noexcept { inventory_ = prepared.remaining_inventory; }

RichonlineCardDiscardRequest50 parse_richonline_card_discard50(View plain) {
    if (plain.size()!=6 || read_le(plain.first(2))!=50) throw CodecError("richonline_card_discard_wire_invalid");
    const auto slot=static_cast<std::int8_t>(plain[4]);
    if (slot<0 || slot>=8) throw CodecError("richonline_card_discard_slot_invalid");
    return {static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),slot,plain[5]};
}
RichonlineTargetCardRequest parse_richonline_target_card(View plain) {
    if (plain.size()<2) throw CodecError("richonline_target_card_wire_invalid");
    const auto opcode=read_le(plain.first(2));
    if ((opcode!=109 && opcode!=111 && opcode!=124 && opcode!=133) || plain.size()!=(opcode==109 ? 8U : 10U))
        throw CodecError("richonline_target_card_wire_invalid");
    if (opcode!=109 && (plain[8]!=0 || plain[9]!=1)) throw CodecError("richonline_target_card_constructor_invalid");
    RichonlineTargetCardRequest request{static_cast<RichonlineTargetCard>(opcode),
        static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),static_cast<std::int8_t>(plain[4]),
        static_cast<std::int8_t>(plain[5]),static_cast<std::int16_t>(read_le(plain.subspan(6,2)))};
    if (request.inventory_slot<0 || request.inventory_slot>=8 || request.inventory_bank!=0 || request.target<0)
        throw CodecError("richonline_target_card_request_invalid");
    return request;
}
Bytes encode_richonline_card_discard4033(std::uint16_t game_id,std::int8_t slot,std::int8_t actor) {
    if (slot<0 || slot>=8 || actor<0 || actor>=4) throw CodecError("richonline_card_discard_response_invalid");
    Bytes result; append_le(result,0x4033,2); append_le(result,game_id,2);
    result.push_back(static_cast<std::uint8_t>(slot)); result.push_back(static_cast<std::uint8_t>(actor)); return result;
}
namespace {
Bytes target_confirmation(std::uint16_t game_id,const RichonlineTargetCardRequest& request,std::uint16_t opcode) {
    if (request.inventory_slot<0 || request.inventory_slot>=8 || request.inventory_bank!=0 || request.target<0)
        throw CodecError("richonline_target_card_request_invalid");
    Bytes result; append_le(result,opcode,2); append_le(result,game_id,2);
    result.push_back(static_cast<std::uint8_t>(request.inventory_slot)); result.push_back(static_cast<std::uint8_t>(request.inventory_bank));
    append_le(result,static_cast<std::uint16_t>(request.target),2); return result;
}
}
Bytes encode_richonline_mine40bd(std::uint16_t game_id,const RichonlineTargetCardRequest& request) {
    if (request.kind!=RichonlineTargetCard::mine1044) throw CodecError("richonline_target_card_kind_invalid");
    return target_confirmation(game_id,request,0x40bd);
}
Bytes encode_richonline_missile40bf(std::uint16_t game_id,const RichonlineTargetCardRequest& request,std::int8_t attacker) {
    if (request.kind!=RichonlineTargetCard::missile1046) throw CodecError("richonline_target_card_kind_invalid");
    if (attacker<0 || attacker>=8) throw CodecError("richonline_target_card_attacker_invalid");
    auto result=target_confirmation(game_id,request,0x40bf);
    result.push_back(static_cast<std::uint8_t>(attacker)); result.push_back(0); return result;
}
Bytes encode_richonline_nuclear40cc(std::uint16_t game_id,const RichonlineTargetCardRequest& request,std::int8_t attacker) {
    if(request.kind!=RichonlineTargetCard::nuclear1063) throw CodecError("richonline_target_card_kind_invalid");
    if(attacker<0 || attacker>=8) throw CodecError("richonline_target_card_attacker_invalid");
    auto result=target_confirmation(game_id,request,0x40cc);
    result.push_back(static_cast<std::uint8_t>(attacker));result.push_back(0);return result;
}
Bytes encode_richonline_safe_nuclear40d5(std::uint16_t game_id,const RichonlineTargetCardRequest& request,std::int8_t attacker) {
    if(request.kind!=RichonlineTargetCard::safe_nuclear1075) throw CodecError("richonline_target_card_kind_invalid");
    if(attacker<0 || attacker>=8) throw CodecError("richonline_target_card_attacker_invalid");
    auto result=target_confirmation(game_id,request,0x40d5);
    result.push_back(static_cast<std::uint8_t>(attacker));result.push_back(0);return result;
}
RichonlineFixedStepCardRequest parse_richonline_fixed_step_card(View bytes) {
    if(bytes.size()!=6) throw CodecError("richonline_fixed_step_card_wire_invalid");
    RichonlineFixedStepCardRequest r{static_cast<std::uint16_t>(read_le(bytes.first(2))),
        static_cast<std::uint16_t>(read_le(bytes.subspan(2,2))),static_cast<std::int8_t>(bytes[4]),
        static_cast<std::int8_t>(bytes[5])};
    if(r.opcode<137 || r.opcode>140 || r.slot<0 || r.slot>=8 || r.bank!=0)
        throw CodecError("richonline_fixed_step_card_fields_invalid");
    return r;
}
RichonlineFixedStepCardPlan plan_richonline_fixed_step_card(std::uint16_t game,
    const RichonlineFixedStepCardRequest& r,std::uint16_t calendar,const RichonlineBossCards& cards) {
    if(r.opcode<137 || r.opcode>140 || r.slot<0 || r.slot>=8 || r.bank!=0)
        throw CodecError("richonline_fixed_step_card_fields_invalid");
    if(r.calendar!=calendar) throw CodecError("richonline_fixed_step_card_calendar_mismatch");
    const auto consumption=cards.prepare_consumption(r.slot,static_cast<std::int16_t>(r.opcode+943));
    if(!consumption) throw CodecError("richonline_fixed_step_card_not_owned");
    Bytes confirmation;append_le(confirmation,r.opcode+0x4050,2);append_le(confirmation,game,2);
    confirmation.push_back(static_cast<std::uint8_t>(r.slot));confirmation.push_back(static_cast<std::uint8_t>(r.bank));
    return {std::move(confirmation),*consumption,static_cast<std::uint8_t>(r.opcode-135)};
}
RichonlineCosmeticCardRequest parse_richonline_cosmetic_card(View bytes) {
    if(bytes.size()!=6) throw CodecError("richonline_cosmetic_card_wire_invalid");
    RichonlineCosmeticCardRequest r{static_cast<RichonlineCosmeticCard>(read_le(bytes.first(2))),
        static_cast<std::uint16_t>(read_le(bytes.subspan(2,2))),static_cast<std::int8_t>(bytes[4]),
        static_cast<std::int8_t>(bytes[5])};
    if((r.kind!=RichonlineCosmeticCard::cracker1117 && r.kind!=RichonlineCosmeticCard::fireworks1118 &&
        r.kind!=RichonlineCosmeticCard::love1127 && r.kind!=RichonlineCosmeticCard::starlight1131) ||
        r.slot<0 || r.slot>=8 || r.bank!=0) throw CodecError("richonline_cosmetic_card_fields_invalid");
    return r;
}
RichonlineCosmeticCardPlan plan_richonline_cosmetic_card(std::uint16_t game,
    const RichonlineCosmeticCardRequest& r,std::uint16_t calendar,const RichonlineBossCards& cards) {
    if((r.kind!=RichonlineCosmeticCard::cracker1117 && r.kind!=RichonlineCosmeticCard::fireworks1118 &&
        r.kind!=RichonlineCosmeticCard::love1127 && r.kind!=RichonlineCosmeticCard::starlight1131) ||
        r.slot<0 || r.slot>=8 || r.bank!=0) throw CodecError("richonline_cosmetic_card_fields_invalid");
    if(r.calendar!=calendar) throw CodecError("richonline_cosmetic_card_calendar_mismatch");
    const auto id=r.kind==RichonlineCosmeticCard::love1127 ? 1127 : r.kind==RichonlineCosmeticCard::starlight1131 ?
        1131 : static_cast<std::int16_t>(static_cast<std::uint16_t>(r.kind)+973);
    const auto consumption=cards.prepare_consumption(r.slot,static_cast<std::int16_t>(id));
    if(!consumption) throw CodecError("richonline_cosmetic_card_not_owned");
    Bytes response;append_le(response,static_cast<std::uint16_t>(r.kind)+0x4050,2);append_le(response,game,2);
    response.push_back(static_cast<std::uint8_t>(r.slot));response.push_back(static_cast<std::uint8_t>(r.bank));
    return {std::move(response),*consumption};
}
}
