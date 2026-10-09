#include "richonline_hibernate_card.hpp"
#include "original_options.hpp"
#include <charconv>
#include <utility>

namespace richnet {
namespace {
void validate(const RichonlineHibernateRequest& r) {
    if(r.inventory_slot<0 || r.inventory_slot>=8 || r.inventory_bank!=0)
        throw CodecError("richonline_hibernate_inventory_fields_invalid");
}
bool eligible(const RichonlineHibernateActor& a) {
    return a.present && a.raw1493==-1 && a.raw1494==-1 && a.raw1495==-1 && a.raw1497==-1 && a.status.frozen==0;
}
std::string_view trim(std::string_view s) {
    const auto at=s.find_first_not_of(" \t\r");
    return at==s.npos ? std::string_view{} : s.substr(at,s.find_last_not_of(" \t\r")-at+1);
}
int number(std::string_view s) {
    s=trim(s);int n=0;const auto r=std::from_chars(s.data(),s.data()+s.size(),n);
    if(s.empty() || r.ec!=std::errc{} || r.ptr!=s.data()+s.size()) throw CodecError("richonline_hibernate_gvalue_invalid");
    return n;
}
}
RichonlineHibernateRules RichonlineHibernateRules::parse(std::string_view text) {
    if(text.size()>4U*1024U*1024U || text.find('\0')!=text.npos) throw CodecError("richonline_hibernate_gvalue_invalid");
    bool item=false;std::optional<int> index,value,result;std::set<int> seen;
    const auto finish=[&] {
        if(!item) return;
        if(!index || !value || !seen.insert(*index).second) throw CodecError("richonline_hibernate_gvalue_invalid");
        if(*index==30) result=value;
    };
    while(!text.empty()) {
        const auto end=text.find('\n');auto line=trim(text.substr(0,end));
        if(end==text.npos) text={};else text.remove_prefix(end+1);
        if(line.empty() || line.starts_with("//") || line.front()==';') continue;
        if(line.front()=='[') {finish();item=line=="[ITEM]";index.reset();value.reset();continue;}
        if(!item) continue;
        const auto eq=line.find('=');if(eq==line.npos) throw CodecError("richonline_hibernate_gvalue_invalid");
        const auto key=trim(line.substr(0,eq));
        if(key=="indx") {if(index) throw CodecError("richonline_hibernate_gvalue_invalid");index=number(line.substr(eq+1));}
        else if(key=="value") {if(value) throw CodecError("richonline_hibernate_gvalue_invalid");value=number(line.substr(eq+1));}
    }
    finish();if(!result || *result<1 || *result>127) throw CodecError("richonline_hibernate_duration_invalid");
    return {static_cast<std::uint8_t>(*result)};
}
RichonlineHibernateRules RichonlineHibernateRules::load(const std::filesystem::path& root) {
    const auto data=load_original_kpd(root/"Data"/"GValue.kpd");
    return parse({reinterpret_cast<const char*>(data.data()),data.size()});
}
RichonlineHibernateRequest decode_richonline_hibernate164(View p) {
    if(p.size()!=6) throw CodecError("richonline_hibernate_length");
    if(read_le(p.first(2))!=164) throw CodecError("richonline_hibernate_opcode");
    const RichonlineHibernateRequest r{static_cast<std::uint16_t>(read_le(p.subspan(2,2))),static_cast<std::int8_t>(p[4]),static_cast<std::int8_t>(p[5])};
    validate(r);return r;
}
Bytes encode_richonline_hibernate40f4(std::uint16_t game,const RichonlineHibernateRequest& r) {
    validate(r);Bytes p;append_le(p,0x40f4,2);append_le(p,game,2);
    p.push_back(static_cast<std::uint8_t>(r.inventory_slot));p.push_back(static_cast<std::uint8_t>(r.inventory_bank));return p;
}
RichonlineHibernatePlan plan_richonline_hibernate(const RichonlineHibernateRequest& request,
    std::uint16_t game,std::int8_t requester,std::string_view map,const RichonlineChanceResources& resources,
    const RichonlineHibernateRules& rules,const RichonlineHibernateSnapshot& before) {
    validate(request);
    if(before.game_id!=game) throw CodecError("richonline_hibernate_game_mismatch");
    if(request.calendar!=before.calendar) throw CodecError("richonline_hibernate_calendar_mismatch");
    if(requester<0 || requester>=8 || before.active_actor!=requester) throw CodecError("richonline_hibernate_actor_invalid");
    if(!before.roll_phase || !before.active_actor_can_act) throw CodecError("richonline_hibernate_phase_invalid");
    if(rules.frozen_turns==0 || rules.frozen_turns>127) throw CodecError("richonline_hibernate_duration_invalid");
    std::size_t count=0;
    for(std::size_t i=0;i<before.actors.size();++i) {
        const auto& a=before.actors[i];
        if(!a.present) continue;
        if(a.inventory.actor!=i || a.inventory.owner_actor!=i) throw CodecError("richonline_hibernate_owner_invalid");
        if(a.status.frozen>127) throw CodecError("richonline_hibernate_status_invalid");
        if(eligible(a)) ++count;
    }
    const auto actor=static_cast<std::size_t>(requester),slot=static_cast<std::size_t>(request.inventory_slot);
    if(!eligible(before.actors[actor])) throw CodecError("richonline_hibernate_requester_ineligible");
    if(count<2) throw CodecError("richonline_hibernate_participants_insufficient");
    const auto& selected=before.actors[actor].inventory.main[slot];
    if(selected.card_id!=506 || selected.count<=0) throw CodecError("richonline_hibernate_not_owned");
    RichonlineHibernatePlan p{before,before,{}, {},encode_richonline_hibernate40f4(game,request)};
    auto& used=p.after.actors[actor].inventory.main[slot];if(--used.count==0) used={};
    for(std::size_t i=0;i<before.actors.size();++i) {
        const auto& a=before.actors[i];auto& after=p.after.actors[i];
        if(i==actor) {p.effects[i]=RichonlineHibernateEffect::requester;continue;}
        if(!eligible(a)) continue;
        after.relations1472[actor]=0;
        p.after.actors[actor].relations1472[i]=0;
        const auto protection=resolve_richonline_sleep_protection(map,resources,a.inventory,a.status);
        after.inventory=protection.after;p.consumed_protection[i]=protection.consumed;
        if(a.status.protected_from_status) p.effects[i]=RichonlineHibernateEffect::status_immunity;
        else if(protection.consumed) p.effects[i]=RichonlineHibernateEffect::passive_protection;
        else {after.status.frozen=rules.frozen_turns;p.effects[i]=RichonlineHibernateEffect::frozen;}
    }
    return p;
}
void commit_richonline_hibernate(RichonlineHibernateSnapshot& current,const RichonlineHibernatePlan& p) {
    if(current!=p.before) throw CodecError("richonline_hibernate_snapshot_changed");
    current=p.after;
}
bool richonline_hibernate_begin_turn(RichonlineActorStatus& status) {
    richonline_status_begin_active_turn(status);return status.frozen>0;
}
}
