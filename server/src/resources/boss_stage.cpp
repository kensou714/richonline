#include "richonline_boss_stage.hpp"
#include "original_options.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <map>

namespace richnet {
namespace {
using Record=std::map<std::string,std::string,std::less<>>;
std::string_view trim(std::string_view text) {
    const auto first=text.find_first_not_of(" \t\r");
    return first==text.npos ? std::string_view{} : text.substr(first,text.find_last_not_of(" \t\r")-first+1);
}
void validate_identity(std::string_view name) {
    if (name.size()<=4 || name.size()>=32 || !name.ends_with(".emp") ||
        name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.")!=name.npos ||
        name.find("..")!=name.npos) throw CodecError("richonline_stage_map_unsupported");
}
const std::string& required(const Record& record,std::string_view key) {
    const auto found=record.find(key);
    if (found==record.end()) throw CodecError("richonline_stage_missing:"+std::string(key));
    return found->second;
}
std::int32_t number(const Record& record,std::string_view key) {
    const auto& text=required(record,key);
    std::int32_t value=0;
    const auto result=std::from_chars(text.data(),text.data()+text.size(),value);
    if (result.ec!=std::errc{} || result.ptr!=text.data()+text.size())
        throw CodecError("richonline_stage_number:"+std::string(key));
    return value;
}
std::uint32_t bounded(const Record& record,std::string_view key,std::uint32_t max=2147483647U) {
    const auto value=number(record,key);
    if (value<0 || static_cast<std::uint32_t>(value)>max) throw CodecError("richonline_stage_range:"+std::string(key));
    return static_cast<std::uint32_t>(value);
}
Record select(std::string_view text,std::string_view name) {
    if (text.size()>2*1024*1024) throw CodecError("richonline_stage_table_too_large");
    std::vector<Record> records;
    bool selected=false;
    while (!text.empty()) {
        const auto end=text.find('\n');
        const auto line=trim(text.substr(0,end));
        if (line.size()>4096) throw CodecError("richonline_stage_line_too_large");
        text=end==text.npos ? std::string_view{} : text.substr(end+1);
        if (line.empty() || line.starts_with("//") || line.front()==';') continue;
        if (line.front()=='[') {
            selected=line=="[MAP]";
            if (selected) {
                if (records.size()>=512) throw CodecError("richonline_stage_record_limit");
                records.emplace_back();
            }
        } else if (selected) {
            const auto separator=line.find('=');
            if (separator==line.npos || trim(line.substr(0,separator)).empty())
                throw CodecError("richonline_stage_line_invalid");
            const auto key=trim(line.substr(0,separator));
            if (records.back().size()>=1024) throw CodecError("richonline_stage_field_limit");
            if (!records.back().emplace(key,trim(line.substr(separator+1))).second)
                throw CodecError("richonline_stage_duplicate_key:"+std::string(key));
        }
    }
    const Record* chosen=nullptr;
    for (const auto& record:records) {
        if (required(record,"mapName")!=name) continue;
        if (chosen) throw CodecError("richonline_stage_record_ambiguous");
        chosen=&record;
    }
    if (!chosen) throw CodecError("richonline_stage_map_unsupported");
    return *chosen;
}
std::uint32_t word(View bytes,std::size_t offset) {
    if (offset>bytes.size() || bytes.size()-offset<4) throw CodecError("richonline_stage_EMP_truncated");
    return read_le(bytes.subspan(offset,4));
}
std::uint32_t balance(View bytes,std::size_t offset,std::string_view key) {
    const auto value=word(bytes,offset);
    if (value>2147483647U) throw CodecError("richonline_stage_range:"+std::string(key));
    return value;
}
std::vector<std::uint32_t> player_choices(std::string_view text) {
    std::vector<std::uint32_t> values;
    while (!text.empty()) {
        const auto end=text.find(',');
        const auto item=trim(text.substr(0,end));
        std::uint32_t value=0;
        const auto parsed=std::from_chars(item.data(),item.data()+item.size(),value);
        if (parsed.ec!=std::errc{} || parsed.ptr!=item.data()+item.size() || value<1 || value>4 ||
            std::find(values.begin(),values.end(),value)!=values.end())
            throw CodecError("richonline_stage_player_choices_invalid");
        values.push_back(value);
        if (end==text.npos) break;
        text=trim(text.substr(end+1));
        if (text.empty()) throw CodecError("richonline_stage_player_choices_invalid");
    }
    if (values.empty()) throw CodecError("richonline_stage_player_choices_invalid");
    return values;
}
RichonlineStageReward reward(const Record& record,std::string_view prefix) {
    const auto stem=std::string(prefix);
    RichonlineStageReward value{bounded(record,stem+"Exp"),bounded(record,stem+"Gold"),
        bounded(record,stem+"PropNum",8),{}};
    if (value.item_count==0) return value;
    std::string_view list=required(record,stem+"Prop");
    for (std::uint32_t i=0;i<value.item_count;++i) {
        const auto separator=list.find(',');
        const auto text=trim(list.substr(0,separator));
        std::int32_t item=0;
        const auto parsed=std::from_chars(text.data(),text.data()+text.size(),item);
        if (parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || text.empty())
            throw CodecError("richonline_stage_reward_item_invalid:"+stem);
        value.item_ids.push_back(item);
        if (separator==list.npos) {
            if (i+1<value.item_count) throw CodecError("richonline_stage_reward_list_short:"+stem);
            break;
        }
        list.remove_prefix(separator+1);
    }
    return value;
}
}
RichonlineBossStage parse_richonline_boss_stage(std::string_view text,std::string_view name,const OriginalEmp& map,std::uint32_t category) {
    validate_identity(name);
    const auto record=select(text,name);
    const auto id=bounded(record,"mapIndx");
    if (map.version!=3 || word(map.header,23288)!=3 ||
        word(map.header,23300)!=id || map.width!=word(map.header,23304) || map.height!=word(map.header,23308) ||
        map.width==0 || map.height==0 || static_cast<std::uint64_t>(map.width)*map.height>32768)
        throw CodecError("richonline_stage_map_metadata_mismatch");
    if (map.tail_offset>map.payload.size() || map.payload.size()-map.tail_offset<120)
        throw CodecError("richonline_stage_EMP_truncated");
    RichonlineBossStage stage{};
    stage.category=category;
    stage.map_name=name; stage.map_id=id; stage.mode=3; stage.width=map.width; stage.height=map.height;
    stage.signature=map.signature;
    stage.human={balance(map.payload,map.tail_offset+104,"human_cash"),
        balance(map.payload,map.tail_offset+108,"human_deposit"),balance(map.payload,map.tail_offset+112,"human_tickets")};
    stage.monetary_scale=balance(map.payload,map.tail_offset+116,"monetary_scale");
    stage.wait_seconds=bounded(record,"waitSecond"); stage.game_months=bounded(record,"gameMonth");
    stage.pawn_gold=bounded(record,"pawnGold"); stage.player_selection=bounded(record,"plySelect",4);
    if(record.contains("investBase")) stage.invest_base=bounded(record,"investBase");
    if(record.contains("investReturn")) stage.invest_return=bounded(record,"investReturn");
    stage.first_reward=reward(record,"first"); stage.repeat_reward=reward(record,"again");
    stage.player_count_choices=player_choices(required(record,"plyNum"));
    if (stage.player_selection==0 || std::find(stage.player_count_choices.begin(),stage.player_count_choices.end(),
        stage.player_selection)==stage.player_count_choices.end()) throw CodecError("richonline_stage_player_selection_invalid");
    stage.boss.count=bounded(record,"bossNum"); stage.boss.base_cash=bounded(record,"bossInitCash");
    stage.boss.max_dice=bounded(record,"bossMaxDice"); stage.boss.role=number(record,"bossRole");
    stage.boss.mood=bounded(record,"bossMood");
    if (stage.boss.count!=1) throw CodecError("richonline_stage_boss_count_unsupported");
    if (stage.boss.max_dice==0) throw CodecError("richonline_stage_range:bossMaxDice");
    for (std::size_t i=0;i<richonline_boss_equipment_keys.size();++i) {
        const auto key=richonline_boss_equipment_keys[i];
        if (record.contains(key)) stage.boss.equipment[i]=bounded(record,key);
    }
    const auto& default_key=required(record,"defaultBuild");
    const auto found=std::find(richonline_building_keys.begin(),richonline_building_keys.end(),default_key);
    if (found==richonline_building_keys.end()) throw CodecError("richonline_stage_default_building_invalid");
    stage.default_building_kind=static_cast<std::uint8_t>(11+(found-richonline_building_keys.begin()));
    for (std::size_t i=0;i<richonline_building_keys.size();++i) {
        const auto cap="maxLev_"+std::string(richonline_building_keys[i]);
        const auto skill="bossSkill_"+std::string(richonline_building_keys[i]);
        if (record.contains(cap)) stage.scenario_caps[i]=static_cast<std::uint8_t>(bounded(record,cap,7));
        if (record.contains(skill)) stage.boss.building_skills[i]=static_cast<std::uint8_t>(bounded(record,skill,7));
    }
    return stage;
}
RichonlineBossStage load_richonline_boss_stage(const std::filesystem::path& root,std::string_view name,std::uint32_t category) {
    validate_identity(name);
    const auto bytes=load_original_kpd(root/"Data"/(category==2 ? "BossWar_v.kpd" : "BossWar.kpd"));
    const std::string_view text{reinterpret_cast<const char*>(bytes.data()),bytes.size()};
    if (!std::filesystem::is_regular_file(root/"Map"/name)) throw CodecError("richonline_stage_map_resource_missing");
    return parse_richonline_boss_stage(text,name,
        load_original_emp(root/"Map"/name),category);
}
}
