#include "richonline_actor_status.hpp"
#include "original_options.hpp"
#include <charconv>
#include <limits>

namespace richnet {
namespace {
std::string_view trim(std::string_view s) {
    const auto at=s.find_first_not_of(" \t\r");
    return at==s.npos ? std::string_view{} : s.substr(at,s.find_last_not_of(" \t\r")-at+1);
}
std::int32_t number(std::string_view s) {
    s=trim(s); std::int32_t n=0; const auto r=std::from_chars(s.data(),s.data()+s.size(),n);
    if(s.empty() || r.ec!=std::errc{} || r.ptr!=s.data()+s.size()) throw CodecError("richonline_status_rules_invalid");
    return n;
}
void decrement(std::uint8_t& n) { if(n) --n; }
std::uint8_t timer(std::int32_t n) {
    if(n<1 || n>127) throw CodecError("richonline_status_duration_invalid");
    return static_cast<std::uint8_t>(n);
}
void check_state(const RichonlineActorStatus& state) {
    for(const auto n:{state.one_step,state.six_steps,state.turtle,state.stay,state.sleepwalking,state.frozen,
        state.attack_turns,state.damage_turns}) if(n>127) throw CodecError("richonline_status_state_invalid");
    if(state.one_step && state.six_steps) throw CodecError("richonline_status_state_invalid");
}
}
RichonlineStatusRules RichonlineStatusRules::parse(std::string_view text) {
    if(text.size()>4U*1024U*1024U || text.find('\0')!=text.npos) throw CodecError("richonline_status_rules_invalid");
    std::map<std::int32_t,std::int32_t> values; std::optional<std::int32_t> index,value; bool item=false;
    const auto finish=[&] { if(item) {
        if(!index || !value || !values.emplace(*index,*value).second) throw CodecError("richonline_status_rules_invalid");
    }};
    while(!text.empty()) {
        const auto newline=text.find('\n'); auto line=trim(text.substr(0,newline));
        if(newline==text.npos) text={}; else text.remove_prefix(newline+1);
        if(line.empty() || line.starts_with("//") || line.front()==';') continue;
        if(line.front()=='[') { finish(); item=line=="[ITEM]"; index.reset();value.reset(); continue; }
        if(!item) continue; const auto eq=line.find('='); if(eq==line.npos) throw CodecError("richonline_status_rules_invalid");
        const auto key=trim(line.substr(0,eq));
        if(key=="indx") { if(index) throw CodecError("richonline_status_rules_invalid"); index=number(line.substr(eq+1)); }
        else if(key=="value") { if(value) throw CodecError("richonline_status_rules_invalid"); value=number(line.substr(eq+1)); }
    }
    finish();
    if(!values.contains(18) || !values.contains(8)) throw CodecError("richonline_status_rules_missing");
    // The consumer adds one before the previous-actor end-of-turn decrement.
    if(values.at(18)>126 || values.at(8)>126) throw CodecError("richonline_status_rules_invalid");
    return {timer(values.at(18)),timer(values.at(8))};
}
RichonlineStatusRules RichonlineStatusRules::load(const std::filesystem::path& root) {
    const auto data=load_original_kpd(root/"Data"/"GValue.kpd");
    return parse(std::string_view(reinterpret_cast<const char*>(data.data()),data.size()));
}
RichonlineChanceStatusResult plan_richonline_chance_status(const RichonlineChanceEventTable& table,
    std::string_view map,std::int32_t id,std::uint16_t game,std::span<const std::int32_t> params,
    const RichonlineActorStatus& before,const RichonlineStatusRules& rules,RichonlineSleepProtection sleep,
    std::array<std::uint8_t,2> opaque) {
    const auto& event=table.event(map,id); const auto category=event.category;
    if(category<7 || category>16) throw CodecError("richonline_chance_event_not_status");
    const std::size_t count=category==10 || category==11 ? 1 : category>=12 && category<=15 ? 2 : 0;
    if(params.size()!=count) throw CodecError("richonline_status_parameters_invalid");
    if(count) table.validate_scalar_presentation(map,id,params[0]);
    if(count && (params[0]<event.raw_parameters[0] || params[0]>event.raw_parameters[1]))
        throw CodecError("richonline_status_parameters_invalid");
    if(count==1 && params[0]>126) throw CodecError("richonline_status_duration_invalid");
    if(count==2 && (params[1]!=number(event.candidates) ||
        ((category==13 || category==14) && params[0]>100) || params[0]>std::numeric_limits<std::int32_t>::max()-100))
        throw CodecError("richonline_status_parameters_invalid");
    if(sleep.triggered && category!=10) throw CodecError("richonline_status_protection_invalid");
    if(sleep.consumed_inventory_slot && (!sleep.triggered || *sleep.consumed_inventory_slot>=8))
        throw CodecError("richonline_status_protection_invalid");
    check_state(before); auto after=before; bool blocked=false, detached=false, removed=false;
    std::optional<std::uint8_t> consumed;
    if(category<=11 && before.protected_from_status) blocked=true;
    else switch(category) {
        case 7: after.one_step=timer(rules.fixed_step_turns+1); after.six_steps=0; break;
        case 8: after.six_steps=timer(rules.fixed_step_turns+1); after.one_step=0; break;
        case 9: after.turtle=timer(rules.turtle_turns+1); break;
        case 10:
            if(sleep.triggered) { blocked=true; consumed=sleep.consumed_inventory_slot; }
            else after.sleepwalking=timer(params[0]+1);
            break;
        case 11: after.frozen=timer(params[0]+1); break;
        case 12: case 13:
            after.attack_multiplier=static_cast<float>(category==12 ? 100+params[0] : 100-params[0])/100.0F;
            after.attack_turns=timer(params[1]); break;
        case 14: case 15:
            after.damage_multiplier=static_cast<float>(category==14 ? 100-params[0] : 100+params[0])/100.0F;
            after.damage_turns=timer(params[1]); break;
        case 16:
            detached=after.possession.has_value(); removed=after.timed_bomb.has_value();
            after.possession.reset(); after.timed_bomb.reset(); after.timed_bomb_owner.reset(); break;
        default: throw CodecError("richonline_status_category_invalid");
    }
    Bytes packet; append_le(packet,0x4096,2); append_le(packet,game,2); append_le(packet,static_cast<std::uint16_t>(id),2);
    if(count) { packet.insert(packet.end(),opaque.begin(),opaque.end());
        for(const auto parameter:params) append_le(packet,static_cast<std::uint32_t>(parameter),4); }
    return {std::move(packet),after,consumed,blocked,detached,removed};
}
void richonline_status_finish_previous_turn(RichonlineActorStatus& status) {
    check_state(status); decrement(status.one_step); decrement(status.six_steps);
    decrement(status.turtle); decrement(status.stay); decrement(status.sleepwalking);
}
void richonline_status_begin_active_turn(RichonlineActorStatus& status) { check_state(status); decrement(status.frozen); }
void richonline_status_begin_combat_phase(RichonlineActorStatus& status) {
    check_state(status); decrement(status.attack_turns); decrement(status.damage_turns);
}
}
