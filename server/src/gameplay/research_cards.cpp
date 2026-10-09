#include "richonline_research_cards.hpp"
#include "original_game_values.hpp"
#include "original_god_resources.hpp"
#include "richonline_route.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <set>
#include <charconv>

namespace richnet {
namespace {
void validate(const RichonlineResearchCardRequest& r) {
    if(r.card!=RichonlineResearchCard::ice1181 && r.card!=RichonlineResearchCard::poison1182 && r.card!=RichonlineResearchCard::fire1183)
        throw CodecError("richonline_research_card_kind");
    if(r.slot<0 || r.slot>=8 || r.bank!=0) throw CodecError("richonline_research_card_inventory_address");
    if(r.card==RichonlineResearchCard::poison1182) {
        if(r.position || r.poison_activation!=1) throw CodecError("richonline_research_card_poison_fields");
    } else if(!r.position || *r.position<0) throw CodecError("richonline_research_card_target");
}
RichonlineChanceInventory consume(const RichonlineResearchCardRequest& r,const RichonlineResearchCardContext& c,
    const RichonlineChanceInventory& before) {
    validate(r);
    if(c.actor<0 || c.actor>=8 || c.actor!=c.requesting_actor) throw CodecError("richonline_research_card_actor");
    if(!c.roll_phase || !c.can_act) throw CodecError("richonline_research_card_phase");
    if(r.calendar!=c.calendar) throw CodecError("richonline_research_card_calendar");
    const auto slot=static_cast<std::size_t>(r.slot);
    if(before[slot].card_id!=static_cast<std::int16_t>(r.card) || before[slot].count<=0)
        throw CodecError("richonline_research_card_not_owned");
    auto after=before;if(--after[slot].count==0) after[slot]={};return after;
}
bool forbidden(std::int8_t type) { return type==28 || type==58 || type==61; }
void rules_valid(const RichonlineResearchTrapRules& rules) {
    if(!rules.freeze_timer || rules.freeze_timer>127 || rules.fire_radius>8 || !rules.fire_radius ||
        !rules.fire_rounds || rules.fire_rounds>127) throw CodecError("richonline_research_trap_rules");
}
}
RichonlineResearchTrapRules RichonlineResearchTrapRules::parse(std::string_view text) {
    if(text.size()>4U*1024U*1024U || text.find('\0')!=text.npos) throw CodecError("richonline_research_trap_resource");
    const auto trim=[](std::string_view s){const auto at=s.find_first_not_of(" \t\r");return at==s.npos?std::string_view{}:s.substr(at,s.find_last_not_of(" \t\r")-at+1);};
    const auto number=[&](std::string_view s){s=trim(s);int n=0;const auto p=std::from_chars(s.data(),s.data()+s.size(),n);
        if(s.empty() || p.ec!=std::errc{} || p.ptr!=s.data()+s.size()) throw CodecError("richonline_research_trap_resource");return n;};
    std::map<int,int> values;std::optional<int> index,value;bool item=false;
    const auto save=[&]{if(item && (!index || !value || !values.emplace(*index,*value).second)) throw CodecError("richonline_research_trap_resource");};
    while(!text.empty()) {
        const auto newline=text.find('\n');const auto line=trim(text.substr(0,newline));
        if(newline==text.npos)text={};else text.remove_prefix(newline+1);
        if(line.empty() || line.starts_with("//") || line.front()==';')continue;
        if(line.front()=='['){save();item=line=="[ITEM]";index.reset();value.reset();continue;}
        if(!item)continue;const auto equal=line.find('=');if(equal==line.npos)throw CodecError("richonline_research_trap_resource");
        const auto key=trim(line.substr(0,equal));
        if(key=="indx"){if(index)throw CodecError("richonline_research_trap_resource");index=number(line.substr(equal+1));}
        else if(key=="value"){if(value)throw CodecError("richonline_research_trap_resource");value=number(line.substr(equal+1));}
    }
    save();for(const auto key:{13,26,27})if(!values.contains(key) || values.at(key)<1 || values.at(key)>127)throw CodecError("richonline_research_trap_resource");
    RichonlineResearchTrapRules result{static_cast<std::uint8_t>(values.at(13)),static_cast<std::uint8_t>(values.at(26)),static_cast<std::uint8_t>(values.at(27))};rules_valid(result);return result;
}
RichonlineResearchTrapRules RichonlineResearchTrapRules::load(const std::filesystem::path& root) {
    const auto values=load_original_game_values(root/"Data/GValue.kpd");
    const auto byte=[&](int index) {
        const auto value=values.require(index);
        if(value<1 || value>127) throw CodecError("richonline_research_trap_resource");
        return static_cast<std::uint8_t>(value);
    };
    RichonlineResearchTrapRules result{byte(13),byte(26),byte(27)};
    rules_valid(result);return result;
}
RichonlinePoisonRules RichonlinePoisonRules::load(const std::filesystem::path& root) {
    const auto cards=load_original_prop_cards(root/"Data/Prop.kpd");
    const auto found=std::find_if(cards.cards.begin(),cards.cards.end(),[](const auto& card){return card.id==1182;});
    if(found==cards.cards.end() || !found->source_fields.contains("hurt"))
        throw CodecError("richonline_poison_resource_missing");
    const auto& text=found->source_fields.at("hurt");std::int32_t damage=0;
    const auto parsed=std::from_chars(text.data(),text.data()+text.size(),damage);
    const auto range=load_original_game_values(root/"Data/GValue.kpd").require(25);
    if(parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || damage<1 || range<1 || range>4)
        throw CodecError("richonline_poison_resource_invalid");
    return {static_cast<std::uint8_t>(range),static_cast<std::uint32_t>(damage)};
}
RichonlineResearchCardRequest decode_richonline_research_card(View wire) {
    if(wire.size()!=8) throw CodecError("richonline_research_card_length");
    const auto opcode=read_le(wire.first(2));
    if(opcode<155 || opcode>157) throw CodecError("richonline_research_card_opcode");
    RichonlineResearchCardRequest r{static_cast<RichonlineResearchCard>(1181+opcode-155),
        static_cast<std::uint16_t>(read_le(wire.subspan(2,2))),static_cast<std::int8_t>(wire[4]),
        static_cast<std::int8_t>(wire[5]),std::nullopt,1,wire[7]};
    if(opcode==156) r.poison_activation=wire[6];
    else r.position=static_cast<std::int16_t>(read_le(wire.subspan(6,2)));
    validate(r);return r;
}
RichonlineFireTrapRules RichonlineFireTrapRules::load(const std::filesystem::path& root) {
    const auto resources=load_original_npc_resources(root/"Data/Npc.kpd");
    const auto found=std::find_if(resources.records.begin(),resources.records.end(),[](const auto& record){return record.id==26;});
    if(found==resources.records.end() || !found->source_fields.contains("hurt"))
        throw CodecError("richonline_fire_damage_resource_missing");
    const auto& text=found->source_fields.at("hurt");std::int32_t damage=0;
    const auto parsed=std::from_chars(text.data(),text.data()+text.size(),damage);
    if(parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || damage<1)
        throw CodecError("richonline_fire_damage_resource_invalid");
    return {RichonlineResearchTrapRules::load(root),static_cast<std::uint32_t>(damage)};
}
Bytes encode_richonline_research_card_success(std::uint16_t game,const RichonlineResearchCardRequest& r) {
    validate(r);Bytes wire;
    append_le(wire,0x40eb+static_cast<std::uint16_t>(r.card)-1181,2);append_le(wire,game,2);
    wire.push_back(static_cast<std::uint8_t>(r.slot));wire.push_back(static_cast<std::uint8_t>(r.bank));
    if(r.position) append_le(wire,static_cast<std::uint16_t>(*r.position),2);
    else {wire.push_back(r.poison_activation);wire.push_back(r.opaque7);}
    return wire;
}
RichonlineResearchTrapPlan plan_richonline_research_trap(const RichonlineResearchCardRequest& r,
    const RichonlineResearchCardContext& context,const RichonlineResearchTrapMap& map,
    const RichonlineResearchTrapRules& rules,const RichonlineChanceInventory& inventory,const RichonlineGroundSnapshot& ground) {
    auto after_inventory=consume(r,context,inventory);rules_valid(rules);
    if(r.card==RichonlineResearchCard::poison1182) throw CodecError("richonline_research_card_not_trap");
    const auto count=static_cast<std::uint32_t>(map.width)*map.height;
    if(!map.width || !map.height || count>32768 || !map.cell || static_cast<std::uint32_t>(*r.position)>=count)
        throw CodecError("richonline_research_trap_map");
    if(!map.center_visible) throw CodecError("richonline_research_trap_visibility");
    auto after=ground.objects;
    if(r.card==RichonlineResearchCard::ice1181) {
        const auto cell=map.cell(*r.position);
        if(!cell.walkable || cell.actor_occupied || forbidden(cell.static_type) || cell.static_type==2 || cell.static_type==3 || after.contains(*r.position))
            throw CodecError("richonline_research_ice_target");
        after.emplace(*r.position,RichonlineGroundObject{25,255,255});
    } else {
        if(map.fire_owner!=context.actor && map.fire_owner!=-1) throw CodecError("richonline_research_fire_owner");
        const int x=*r.position%map.width,y=*r.position/map.width,radius=rules.fire_radius;
        for(int row=std::max(0,y-radius);row<=std::min(static_cast<int>(map.height)-1,y+radius);++row)
            for(int col=std::max(0,x-radius);col<=std::min(static_cast<int>(map.width)-1,x+radius);++col) {
                const auto position=static_cast<std::int16_t>(row*map.width+col);const auto cell=map.cell(position);
                if(!cell.walkable || cell.actor_occupied || forbidden(cell.static_type) || after.contains(position)) continue;
                after.emplace(position,RichonlineGroundObject{26,static_cast<std::uint8_t>(map.fire_owner),rules.fire_rounds});
            }
        // NEW consumes the card even if every cell in the chosen square is excluded.
    }
    return {ground,std::move(after),inventory,std::move(after_inventory),encode_richonline_research_card_success(context.game,r)};
}
RichonlineIceTrapLanding plan_richonline_ice_trap_landing(std::int16_t position,
    const RichonlineGroundSnapshot& ground,const RichonlineActorStatus& status,const RichonlineResearchTrapRules& rules) {
    rules_valid(rules);const auto it=ground.objects.find(position);
    if(it==ground.objects.end() || it->second.npc!=25) throw CodecError("richonline_research_ice_absent");
    auto after_ground=ground.objects;after_ground.erase(position);auto after_status=status;
    if(!status.protected_from_status) after_status.frozen=rules.freeze_timer;
    return {ground,std::move(after_ground),status,after_status,status.protected_from_status};
}
RichonlineFireTrapTick plan_richonline_fire_trap_tick(const RichonlineGroundSnapshot& ground,
    std::uint8_t current,bool anchor,std::span<const bool> active) {
    if(active.empty() || active.size()>8 || current>=active.size())throw CodecError("richonline_research_fire_clock");
    auto after=ground.objects;
    for(auto it=after.begin();it!=after.end();) {
        auto& object=it->second;if(object.npc!=26){++it;continue;}
        if(object.byte8>127 || (object.byte7!=255 && object.byte7>=active.size())) throw CodecError("richonline_research_fire_record");
        const bool inactive_owner=object.byte7==255 || !active[object.byte7];
        if(inactive_owner?anchor:object.byte7==current) {if(object.byte8)--object.byte8;if(!object.byte8){it=after.erase(it);continue;}}
        ++it;
    }
    return {ground,std::move(after)};
}
RichonlineGameFundsUpdate plan_richonline_fire_trap_damage(std::uint8_t victim,
    const RichonlineGameFundsSnapshot& expected,std::uint32_t damage) {
    const auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if(victim>=8 || !damage || damage>maximum || !expected.funds.deposit || expected.funds.cash>maximum || *expected.funds.deposit>maximum)
        throw CodecError("richonline_research_fire_damage");
    auto after=expected.funds;
    if(after.cash>=damage) after.cash-=damage;
    else {const auto deficit=damage-after.cash;after.cash=0;after.deposit=*after.deposit>deficit?*after.deposit-deficit:0;}
    return {victim,expected,after};
}
std::vector<RichonlinePoisonCell> richonline_poison_footprint(std::int16_t origin,std::uint8_t range,const RichonlinePoisonStep& step) {
    if(origin<0 || !range || range>4 || !step) throw CodecError("richonline_poison_topology");
    std::vector<RichonlinePoisonCell> result{{origin,0}};
    std::array<std::int16_t,4> rays{origin,origin,origin,origin};
    // Match NEW639170 ordering and retain repeated positions if topology merges.
    for(std::uint8_t layer=0;layer<range;++layer) for(std::uint8_t direction=0;direction<4;++direction) {
        const auto next=step(rays[direction],direction);
        if(next) {if(*next<0) throw CodecError("richonline_poison_topology");rays[direction]=*next;result.push_back({*next,layer});}
    }
    return result;
}
std::vector<RichonlinePoisonCell> richonline_poison_map_footprint(const RichonlineRoadTopology& map,
    std::int16_t origin,std::uint8_t range) {
    if(!map.cell(origin).walkable) throw CodecError("richonline_poison_origin_invalid");
    auto result=richonline_poison_footprint(origin,range,[&](std::int16_t position,std::uint8_t direction)->std::optional<std::int16_t> {
        const auto width=static_cast<std::int32_t>(map.width()),height=static_cast<std::int32_t>(map.height());
        const auto x=position%width,y=position/width;
        if(direction==0 && y+1<height) return static_cast<std::int16_t>(position+width);
        if(direction==1 && x>0) return static_cast<std::int16_t>(position-1);
        if(direction==2 && y>0) return static_cast<std::int16_t>(position-width);
        if(direction==3 && x+1<width) return static_cast<std::int16_t>(position+1);
        return {};
    });
    std::erase_if(result,[&](const auto& cell){return !map.cell(cell.position).walkable;});
    return result;
}
RichonlinePoisonPlan plan_richonline_poison_card(const RichonlineResearchCardRequest& r,
    const RichonlineResearchCardContext& context,const RichonlineChanceInventory& inventory,
    std::uint32_t use_count,std::uint32_t base,std::span<const RichonlinePoisonCell> footprint,
    std::span<const RichonlinePoisonVictim> victims) {
    auto after_inventory=consume(r,context,inventory);
    if(r.card!=RichonlineResearchCard::poison1182) throw CodecError("richonline_research_card_not_poison");
    constexpr auto maximum=static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if(use_count>=maximum || !base || base>maximum || footprint.empty() || footprint.size()>17 || victims.size()>8)
        throw CodecError("richonline_poison_context");
    for(const auto& cell:footprint)
        if(cell.position<0 || cell.attenuation_layer>3) throw CodecError("richonline_poison_footprint");
    RichonlinePoisonPlan plan{inventory,std::move(after_inventory),use_count,use_count+1,{}, {},encode_richonline_research_card_success(context.game,r)};
    std::set<std::uint8_t> seen;
    for(const auto& victim:victims) {
        if(victim.actor>=8 || !seen.insert(victim.actor).second || victim.position<0)
            throw CodecError("richonline_poison_victim");
        if(!victim.active || victim.actor==static_cast<std::uint8_t>(context.actor) || victim.hospital || victim.prison || victim.excluded1497) continue;
        auto after=victim.funds.funds;bool hit=false;
        for(const auto& cell:footprint) {
            if(cell.position!=victim.position) continue;
            if(!victim.adjusted_damage || victim.adjusted_damage>maximum || !after.deposit || after.cash>maximum || *after.deposit>maximum)
                throw CodecError("richonline_poison_damage_unresolved");
            // 7CE420 uses float conversion before the double percentage division.
            const auto ratio=static_cast<std::int64_t>(static_cast<double>(static_cast<float>(victim.adjusted_damage))*100.0/static_cast<double>(static_cast<float>(base))+0.5);
            const auto attenuated=static_cast<std::int64_t>(victim.adjusted_damage)-ratio*5*cell.attenuation_layer;
            const double amount=static_cast<double>(attenuated)*(1.0+0.5*static_cast<double>(use_count/3));
            if(amount>maximum || amount< -static_cast<double>(maximum)) throw CodecError("richonline_poison_damage_overflow");
            const auto damage=static_cast<std::int64_t>(amount); // NEW ftol2 truncates.
            const auto cash=static_cast<std::int64_t>(after.cash)-damage;
            if(cash>maximum) throw CodecError("richonline_poison_cash_overflow");
            if(cash>=0) after.cash=static_cast<std::uint32_t>(cash);
            else {after.cash=0;after.deposit=static_cast<std::uint32_t>(std::max<std::int64_t>(0,static_cast<std::int64_t>(*after.deposit)+cash));}
            hit=true;
        }
        if(hit) {plan.funds.push_back({victim.actor,victim.funds,after});if(after.cash==0 && *after.deposit==0) plan.bankrupt.push_back(victim.actor);}
    }
    return plan;
}
} // namespace richnet
