#include "richonline_combat_resources.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <limits>

namespace richnet {
namespace {
std::string_view trim(std::string_view text) {
    const auto first=text.find_first_not_of(" \t\r");
    return first==text.npos?std::string_view{}:text.substr(first,text.find_last_not_of(" \t\r")-first+1);
}
std::int32_t integer(std::string_view text) {
    text=trim(text); std::int32_t result=0;
    const auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
    if (text.empty() || parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || result<0)
        throw CodecError("richonline_combat_resource_integer_invalid");
    return result;
}
std::map<std::string,std::map<std::string,std::string>> sections(std::string_view text) {
    if (text.empty() || text.size()>4U*1024U*1024U || text.find('\0')!=text.npos)
        throw CodecError("richonline_combat_resource_text_invalid");
    std::map<std::string,std::map<std::string,std::string>> result;
    std::string section;
    while (!text.empty()) {
        const auto end=text.find('\n'); auto line=trim(text.substr(0,end));
        text=end==text.npos?std::string_view{}:text.substr(end+1);
        if (line.empty() || line.starts_with("//") || line.starts_with(";") || line.starts_with("#")) continue;
        if (line.front()=='[' && line.back()==']') { section=std::string(line.substr(1,line.size()-2)); continue; }
        const auto split=line.find('=');
        if (section.empty() || split==line.npos) throw CodecError("richonline_combat_resource_field_invalid");
        if (!result[section].emplace(std::string(trim(line.substr(0,split))),std::string(trim(line.substr(split+1)))).second)
            throw CodecError("richonline_combat_resource_field_duplicate");
    }
    return result;
}
float building(const std::array<float,8>& levels,std::optional<std::uint8_t> level) {
    if (!level) return 1.0F;
    if (*level==0 || *level>=levels.size()) throw CodecError("richonline_combat_resource_buff_level_invalid");
    return levels[*level];
}
std::vector<std::map<std::string,std::string>> prop_records(std::string_view text) {
    if (text.empty() || text.size()>8U*1024U*1024U || text.find('\0')!=text.npos)
        throw CodecError("richonline_combat_resource_text_invalid");
    std::vector<std::map<std::string,std::string>> result;
    while (!text.empty()) {
        const auto end=text.find('\n'); const auto line=trim(text.substr(0,end));
        text=end==text.npos?std::string_view{}:text.substr(end+1);
        if (line.empty() || line.starts_with("//") || line.starts_with(";") || line.starts_with("#")) continue;
        if (line=="[PROP]") { result.emplace_back(); continue; }
        const auto split=line.find_first_of("=:");
        if (result.empty() || split==line.npos || line.starts_with("["))
            throw CodecError("richonline_combat_resource_prop_field_invalid");
        if (!result.back().emplace(std::string(trim(line.substr(0,split))),std::string(trim(line.substr(split+1)))).second)
            throw CodecError("richonline_combat_resource_field_duplicate");
    }
    return result;
}
}
RichonlineCombatModifierResources RichonlineCombatModifierResources::parse(std::string_view bwb,std::string_view props) {
    RichonlineCombatModifierResources result;
    const auto values=sections(bwb);
    for (const auto* section:{"CHANG","ZHONG"}) {
        const auto found=values.find(section);
        if (found==values.end()) throw CodecError("richonline_combat_resource_building_missing");
        for (std::size_t level=1;level<=7;++level) {
            const auto field=found->second.find("level_"+std::to_string(level));
            if (field==found->second.end()) throw CodecError("richonline_combat_resource_level_missing");
            const auto first=field->second.find(','),last=field->second.rfind(',');
            if (first==field->second.npos || first==last) throw CodecError("richonline_combat_resource_level_invalid");
            (void)integer(std::string_view(field->second).substr(0,first));
            (void)integer(std::string_view(field->second).substr(first+1,last-first-1));
            const auto percent=integer(std::string_view(field->second).substr(last+1));
            const bool attack=std::string_view(section)=="ZHONG";
            if ((!attack && percent>100) || percent>10000) throw CodecError("richonline_combat_resource_percentage_invalid");
            const auto base=attack?100+percent:100-percent;
            (attack?result.attack_building_:result.defense_building_)[level]=static_cast<float>(base)/100.0F;
        }
    }
    const auto props_parsed=prop_records(props);
    std::map<std::uint16_t,bool> seen;
    constexpr std::array<std::string_view,4> keys{"attackV","attackR","defendV","defendR"};
    for (const auto& fields_source:props_parsed) {
        const auto id_field=fields_source.find("indx");
        if (id_field==fields_source.end()) throw CodecError("richonline_combat_resource_prop_invalid");
        const auto raw_id=integer(id_field->second);
        if (raw_id==0 || raw_id>32767) throw CodecError("richonline_combat_resource_prop_invalid");
        const auto id=static_cast<std::uint16_t>(raw_id);
        if (!seen.emplace(id,true).second) throw CodecError("richonline_combat_resource_prop_duplicate");
        result.maximum_prop_=std::max(result.maximum_prop_,id);
        if (!fields_source.contains("att_desc")) continue;
        std::array<Conditional,4> fields{};
        for (std::size_t i=0;i<keys.size();++i) {
            const auto found=fields_source.find(std::string(keys[i]));
            if (found==fields_source.end()) continue; // Constructor zeroes absent attribute triples.
            const auto text=trim(found->second); const auto open=text.find('(');
            fields[i].value=integer(text.substr(0,open));
            if (open!=text.npos) {
                if (text.back()!=')' || open+3>=text.size() || (text[open+1]!='<' && text[open+1]!='>'))
                    throw CodecError("richonline_combat_resource_condition_invalid");
                fields[i].condition=text[open+1];
                fields[i].threshold=integer(text.substr(open+2,text.size()-open-3));
            }
        }
        result.equipment_.emplace(id,fields);
    }
    return result;
}
RichonlineCombatModifierResources RichonlineCombatModifierResources::load(const std::filesystem::path& root) {
    const auto bwb=load_original_kpd(root/"Data"/"BwbValue.kpd",4U*1024U*1024U);
    const auto props=load_original_kpd(root/"Data"/"Prop.kpd",8U*1024U*1024U);
    return parse({reinterpret_cast<const char*>(bwb.data()),bwb.size()},
        {reinterpret_cast<const char*>(props.data()),props.size()});
}
float RichonlineCombatModifierResources::attack_building(std::optional<std::uint8_t> level) const {
    return building(attack_building_,level);
}
float RichonlineCombatModifierResources::defense_building(std::optional<std::uint8_t> level) const {
    return building(defense_building_,level);
}
RichonlineEquipmentCombatTerms RichonlineCombatModifierResources::equipment(
    const std::array<std::uint32_t,32>& words,std::uint32_t cash) const {
    if (cash>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("richonline_combat_resource_cash_invalid");
    std::array<std::int64_t,4> sums{};
    for (const auto word:words) {
        const auto id=static_cast<std::uint16_t>(word&0xfff);
        if (id==0) continue;
        if (id>maximum_prop_) throw CodecError("richonline_combat_resource_equipment_id_invalid");
        const auto found=equipment_.find(id);
        if (found==equipment_.end()) continue; // Verified att_desc gate, including sparse default records.
        for (std::size_t i=0;i<sums.size();++i) {
            const auto& term=found->second[i];
            if (term.condition==0 || (term.condition=='<' && cash<static_cast<std::uint32_t>(term.threshold)) ||
                (term.condition=='>' && cash>static_cast<std::uint32_t>(term.threshold))) sums[i]+=term.value;
            if (sums[i]>std::numeric_limits<std::int32_t>::max()) throw CodecError("richonline_combat_resource_attribute_overflow");
        }
    }
    return {static_cast<std::int32_t>(sums[0]),static_cast<std::int32_t>(sums[1]),
        static_cast<std::int32_t>(sums[2]),static_cast<std::int32_t>(sums[3])};
}
std::array<std::uint32_t,32> RichonlineCombatModifierResources::boss_equipment(const RichonlineBossStage& stage) {
    std::array<std::uint32_t,32> result{};
    for (std::size_t i=0;i<stage.boss.equipment.size();++i) result[i<6?i:i+1]=stage.boss.equipment[i];
    return result;
}
RichonlinePropUseLimits RichonlinePropUseLimits::parse(std::string_view text) {
    if(text.size()>4U*1024U*1024U || text.find('\0')!=text.npos)
        throw CodecError("richonline_prop_limits_text_invalid");
    RichonlinePropUseLimits result;
    bool active=false;
    std::optional<std::uint16_t> prop;
    std::optional<std::string> rule;
    std::optional<std::int32_t> number;
    const auto save=[&] {
        if(!active) return;
        if(!prop || !rule) throw CodecError("richonline_prop_limits_row_incomplete");
        constexpr std::array<std::string_view,5> modes{"CM","PK","TC","BS","KO"};
        const auto mode=std::find(modes.begin(),modes.end(),*rule);
        if(mode==modes.end()) return; // NEW leaves unknown rule names unchanged.
        if(!number) throw CodecError("richonline_prop_limits_row_incomplete");
        result.limits_.insert_or_assign({static_cast<std::uint32_t>(mode-modes.begin()),*prop},*number);
    };
    while(!text.empty()) {
        const auto end=text.find('\n');const auto line=trim(text.substr(0,end));
        text=end==text.npos?std::string_view{}:text.substr(end+1);
        if(line.empty() || line.starts_with("//") || line.starts_with(";") || line.starts_with("#")) continue;
        if(line.front()=='[') {
            if(line.back()!=']') throw CodecError("richonline_prop_limits_section_invalid");
            save();active=line=="[PROP]";prop.reset();rule.reset();number.reset();continue;
        }
        if(!active) continue;
        const auto split=line.find_first_of("=:");
        if(split==line.npos) throw CodecError("richonline_prop_limits_field_invalid");
        const auto key=trim(line.substr(0,split)),value=trim(line.substr(split+1));
        if(key=="prop") {
            const auto id=integer(value);
            if(prop || id>=5000) throw CodecError("richonline_prop_limits_prop_invalid");
            prop=static_cast<std::uint16_t>(id);
        } else if(key=="rule") {
            if(rule || value.empty()) throw CodecError("richonline_prop_limits_rule_invalid");
            rule=std::string(value);
        } else if(key=="num") {
            std::int32_t parsed=0;
            const auto converted=std::from_chars(value.data(),value.data()+value.size(),parsed);
            if(number || value.empty() || converted.ec!=std::errc{} || converted.ptr!=value.data()+value.size() || parsed<-1)
                throw CodecError("richonline_prop_limits_num_invalid");
            number=parsed;
        }
    }
    save();return result;
}
RichonlinePropUseLimits RichonlinePropUseLimits::load(const std::filesystem::path& root) {
    const auto path=root/"Data"/"Grant.kpd";
    std::error_code error;
    const bool present=std::filesystem::exists(path,error);
    if(error) throw CodecError("richonline_prop_limits_file_probe_failed");
    if(!present) return {}; // Verified NEW constructor defaults, not guessed limits.
    const auto text=load_original_kpd(path);
    return parse({reinterpret_cast<const char*>(text.data()),text.size()});
}
std::int32_t RichonlinePropUseLimits::limit(std::uint32_t mode,std::uint16_t prop) const {
    if(prop>=5000) throw CodecError("richonline_prop_limits_prop_invalid");
    if(mode>4) return -1;
    const auto found=limits_.find({mode,prop});
    return found==limits_.end()?-1:found->second;
}
bool RichonlinePropUseLimits::allows(std::uint32_t mode,std::uint16_t prop,std::uint16_t previous) const {
    const auto maximum=limit(mode,prop);
    return maximum==-1 || static_cast<std::int32_t>(previous)+1<=maximum;
}
std::optional<RichonlineBossCards::PreparedConsumption> prepare_richonline_safety_helmet(
    const RichonlineChanceInventory& inventory,std::uint16_t previous,std::uint32_t mode,
    const RichonlinePropUseLimits& limits,bool eligible) {
    if(!limits.allows(mode,1076,previous) || !eligible) return {};
    for(std::size_t slot=0;slot<inventory.size();++slot) if(inventory[slot].card_id==1076) {
        if(inventory[slot].count<=0) throw CodecError("richonline_safety_helmet_inventory_invalid");
        auto after=inventory;
        if(--after[slot].count==0) after[slot]={};
        return RichonlineBossCards::PreparedConsumption{inventory,after,static_cast<std::int8_t>(slot),1076};
    }
    return {};
}
}
