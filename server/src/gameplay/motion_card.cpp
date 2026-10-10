#include "richonline_motion_card.hpp"
#include "original_options.hpp"
#include <charconv>

namespace richnet {
namespace {
bool motion_opcode(std::uint64_t opcode) {
    return (opcode>=104 && opcode<=107) || opcode==136 || opcode==141;
}
std::string_view trim(std::string_view s) {
    const auto begin=s.find_first_not_of(" \t\r");
    return begin==s.npos ? std::string_view{} : s.substr(begin,s.find_last_not_of(" \t\r")-begin+1);
}
int number(std::string_view s) {
    s=trim(s); int value{}; const auto parsed=std::from_chars(s.data(),s.data()+s.size(),value);
    if(s.empty() || parsed.ec!=std::errc{} || parsed.ptr!=s.data()+s.size()) throw CodecError("richonline_motion_rules_invalid");
    return value;
}
}
RichonlineMotionCardRules RichonlineMotionCardRules::load(const std::filesystem::path& root) {
    const auto bytes=load_original_kpd(root/"Data"/"GValue.kpd");
    std::string_view text(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    std::optional<int> id; std::map<int,int> values;
    while(!text.empty()) {
        const auto end=text.find('\n'); auto line=trim(text.substr(0,end));
        if(end==text.npos) text={}; else text.remove_prefix(end+1);
        if(line.empty() || line.starts_with("//")) continue;
        if(line.front()=='[') {id.reset();continue;}
        const auto eq=line.find('=');if(eq==line.npos) continue;
        const auto key=trim(line.substr(0,eq));
        if(key=="indx") id=number(line.substr(eq+1));
        else if(key=="value" && id && (*id==7 || *id==8 || *id==9 || *id==11 || *id==18)) {
            if(!values.emplace(*id,number(line.substr(eq+1))).second) throw CodecError("richonline_motion_rules_invalid");
        }
    }
    if(!values.contains(7) || !values.contains(8) || !values.contains(9) || !values.contains(11) || !values.contains(18) ||
        values.at(7)<1 || values.at(7)>127 || values.at(8)<1 || values.at(8)>127 ||
        values.at(18)<1 || values.at(18)>127 || values.at(9)<1 || values.at(9)>127 || values.at(11)<1 || values.at(11)>127)
        throw CodecError("richonline_motion_rules_invalid");
    return {static_cast<std::uint8_t>(values.at(7)),static_cast<std::uint8_t>(values.at(8)),
        static_cast<std::uint8_t>(values.at(18)),static_cast<std::uint8_t>(values.at(9)),static_cast<std::uint8_t>(values.at(11))};
}
RichonlineMotionCardRequest parse_richonline_motion_card(View plain) {
    if(plain.size()!=8) throw CodecError("richonline_motion_card_wire_invalid");
    const auto opcode=read_le(plain.first(2));
    if(!motion_opcode(opcode)) throw CodecError("richonline_motion_card_opcode_invalid");
    RichonlineMotionCardRequest result{static_cast<RichonlineMotionCard>(opcode),
        static_cast<std::uint16_t>(read_le(plain.subspan(2,2))),static_cast<std::int8_t>(plain[4]),
        static_cast<std::int8_t>(plain[5]),static_cast<std::int8_t>(plain[6]),plain[7]};
    if(result.slot<0 || result.slot>=8 || result.bank!=0 || result.target_actor<0 || result.target_actor>=8)
        throw CodecError("richonline_motion_card_fields_invalid");
    return result;
}
RichonlineMotionCardPlan plan_richonline_motion_card(std::uint16_t game_id,
    const RichonlineMotionCardRequest& request,std::uint16_t counter,std::int8_t active_actor,
    const RichonlineMotionCardTarget& target,const RichonlineMotionCardRules& rules,
    const RichonlineRoadTopology& topology,const RichonlineRouteChooser& chooser,const RichonlineBossCards& cards) {
    static_cast<void>(chooser);
    const auto opcode=static_cast<std::uint16_t>(request.kind);
    if(!motion_opcode(opcode) || request.slot<0 || request.slot>=8 || request.bank!=0 ||
        request.target_actor<0 || request.target_actor>=8 || active_actor<0 || active_actor>=8)
        throw CodecError("richonline_motion_card_fields_invalid");
    if(request.calendar_counter!=counter) throw CodecError("richonline_motion_card_counter_mismatch");
    if(target.actor!=request.target_actor || !target.active || !target.in_target_selection || target.heading>3 ||
        !topology.cell(target.position).walkable) throw CodecError("richonline_motion_card_target_invalid");
    if(!rules.stay_turns || rules.stay_turns>127 || !rules.turtle_turns || rules.turtle_turns>127)
        throw CodecError("richonline_motion_rules_invalid");
    const bool step_card=request.kind==RichonlineMotionCard::one_step1079 || request.kind==RichonlineMotionCard::six_steps1084;
    if(step_card && (!rules.fixed_step_turns || rules.fixed_step_turns>127))
        throw CodecError("richonline_motion_rules_invalid");
    const auto consumed=cards.prepare_consumption(request.slot,static_cast<std::int16_t>(opcode+(step_card?943:935)));
    if(!consumed) throw CodecError("richonline_motion_card_not_owned");
    auto after=target;
    const bool blocked=request.kind!=RichonlineMotionCard::reverse1040 && target.status.protected_from_status;
    if(request.kind==RichonlineMotionCard::reverse1040) {
        const auto& cell=topology.cell(target.position);
        const auto reverse=static_cast<std::uint8_t>((target.heading+2U)&3U);
        if(cell.neighbors[target.heading] || cell.neighbors[reverse]) after.heading=reverse;
        else {
            std::optional<std::uint8_t> side;
            for(std::uint8_t direction=0;direction<4;++direction) if(cell.neighbors[direction]) {
                if(side) throw CodecError("richonline_motion_reverse_heading_ambiguous");
                side=direction;
            }
            if(!side) throw CodecError("richonline_motion_card_target_invalid");
            after.heading=static_cast<std::uint8_t>((*side+2U)&3U);
        }
    } else if(request.kind==RichonlineMotionCard::sleep1042) {
        if(!rules.sleep_turns || rules.sleep_turns>127) throw CodecError("richonline_motion_rules_invalid");
        if(!blocked) after.status.sleepwalking=rules.sleep_turns;
    } else if(!blocked) {
        after.status.one_step=0; after.status.six_steps=0;after.status.turtle=0;after.status.stay=0;
        if(request.kind==RichonlineMotionCard::turtle1039) after.status.turtle=rules.turtle_turns;
        else if(request.kind==RichonlineMotionCard::stay1041) after.status.stay=rules.stay_turns;
        // 40D8/40DD clear self status; self movement follows in4011. Other
        // targets retain GValue[18] until their own end-of-turn decrement.
        else if(target.actor!=active_actor) {
            if(request.kind==RichonlineMotionCard::one_step1079) after.status.one_step=rules.fixed_step_turns;
            else after.status.six_steps=rules.fixed_step_turns;
        }
    }
    Bytes response;append_le(response,opcode+0x4050,2);append_le(response,game_id,2);
    response.push_back(static_cast<std::uint8_t>(request.slot));response.push_back(static_cast<std::uint8_t>(request.bank));
    response.push_back(static_cast<std::uint8_t>(target.actor));
    const bool self_stay=request.kind==RichonlineMotionCard::stay1041 && target.actor==active_actor;
    const bool self_step=step_card && target.actor==active_actor;
    return {std::move(response),*consumed,target,after,self_stay && !blocked ?
        RichonlineMotionCardContinuation::await_same_position17 : RichonlineMotionCardContinuation::resume_controls,
        blocked,(self_stay || self_step) && blocked ? std::optional{encode_richonline_dice_recovery400b(game_id)} : std::nullopt,
        self_step && !blocked ? std::optional<std::uint8_t>{request.kind==RichonlineMotionCard::one_step1079 ?
            std::uint8_t{1}:std::uint8_t{6}} : std::nullopt};
}
}
