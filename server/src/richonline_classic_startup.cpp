#include "richonline_classic_startup.hpp"
#include "richonline_combat_resources.hpp"
#include "richonline_initial_cash.hpp"
#include "original_options.hpp"

#include <algorithm>
#include <charconv>
#include <map>
#include <set>

namespace richnet {
namespace {
using Sections=std::map<std::string,std::map<std::string,std::string,std::less<>>,std::less<>>;
std::string_view trim(std::string_view text) {
    const auto begin=text.find_first_not_of(" \t\r");
    return begin==text.npos ? std::string_view{} : text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);
}
Sections sections(const std::filesystem::path& file) {
    const auto bytes=load_original_kpd(file);
    std::string_view text(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    if(text.find('\0')!=text.npos) throw CodecError("richonline_classic_options_text_invalid");
    Sections result;
    std::string current;
    while(!text.empty()) {
        const auto end=text.find('\n');const auto line=trim(text.substr(0,end));
        text=end==text.npos ? std::string_view{} : text.substr(end+1);
        if(line.empty() || line.front()==';' || line.front()=='#' || line.starts_with("//")) continue;
        if(line.front()=='[' && line.back()==']') {
            current=std::string(line.substr(1,line.size()-2));
            if(!result.emplace(current,Sections::mapped_type{}).second)
                throw CodecError("richonline_classic_options_duplicate_section");
            continue;
        }
        const auto split=line.find_first_of("=:");
        if(current.empty() || split==line.npos ||
            !result.at(current).emplace(trim(line.substr(0,split)),trim(line.substr(split+1))).second)
            throw CodecError("richonline_classic_options_field_invalid");
    }
    return result;
}
std::uint32_t number(const Sections& values,std::string_view section,std::string_view key) {
    const auto group=values.find(section);
    if(group==values.end()) throw CodecError("richonline_classic_options_section_missing");
    const auto field=group->second.find(key);
    if(field==group->second.end()) throw CodecError("richonline_classic_options_key_missing");
    const auto& text=field->second;std::uint32_t result=0;
    const auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
    if(text.empty() || parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size() || result>2147483647U)
        throw CodecError("richonline_classic_options_number_invalid");
    return result;
}
void choice(const Sections& values,std::string_view section,std::string_view prefix,
    std::size_t count,std::uint32_t selected) {
    bool found=false;
    for(std::size_t i=0;i<count;++i)
        found=number(values,section,std::string(prefix)+std::to_string(i))==selected || found;
    if(!found) throw CodecError("richonline_classic_option_not_available");
}
std::uint32_t word(View bytes,std::size_t offset) {
    if(offset>bytes.size() || bytes.size()-offset<4) throw CodecError("richonline_classic_resource_truncated");
    return read_le(bytes.subspan(offset,4));
}
}
RichonlineClassicStartup build_richonline_classic_startup(const std::filesystem::path& root,
    const RichonlineRoomSnapshot& room,RichonlineBoardInit header,std::uint32_t calendar,
    std::span<const RichonlineClassicPlayer> players,RichonlineMapSpawnPolicy spawn_policy,
    const std::function<std::size_t(std::size_t)>& random) {
    const View e(room.description.extension),record(room.description.record);
    if(e.size()!=88 || word(record,120)!=88 || (word(record,32)&0x40U)==0)
        throw CodecError("richonline_classic_E88_invalid");
    if(word(e,48)!=0 || word(record,36)!=0)
        throw CodecError("richonline_classic_mode_unsupported");
    const auto capacity=word(e,52),wait=word(e,56),months=word(e,60),pawn=word(e,64),category=word(e,68);
    if(capacity<2 || capacity>4 || players.size()!=capacity || room.participants.size()!=capacity ||
        word(record,40)!=capacity || category>3 || !header.participants.empty())
        throw CodecError("richonline_classic_membership_invalid");
    const auto name_end=std::find(e.begin(),e.begin()+32,std::uint8_t{0});
    const std::string name(e.begin(),name_end);
    if(name_end==e.begin()+32 || name.size()<=4 || !name.ends_with(".emp") ||
        name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.")!=name.npos ||
        name.find("..")!=name.npos)
        throw CodecError("richonline_classic_map_name_invalid");
    const auto options=sections(root/"Data"/"Option.kpd");
    choice(options,"PLAYER","sel",3,capacity);
    choice(options,"WAIT","sel",6,wait);
    choice(options,"MONTH","sel",6,months);
    const auto pawns=sections(root/"Data"/"Pawn.kpd");
    constexpr std::array<std::string_view,4> tiers{"PAWN_CHU","PAWN_ZHONG","PAWN_GAO","PAWN_XIN"};
    const auto pawn_count=number(pawns,tiers[category],"num");
    if(pawn_count==0 || pawn_count>8) throw CodecError("richonline_classic_pawn_count_invalid");
    choice(pawns,tiers[category],"item",pawn_count,pawn);
    auto emp=load_original_emp(root/"Map"/name);
    if(word(emp.header,23288)!=0 || !std::equal(emp.signature.begin(),emp.signature.end(),e.begin()+32))
        throw CodecError("richonline_classic_map_identity_mismatch");
    auto topology=richonline_road_topology(emp);
    const auto price=load_original_price_base(root/"Data"/"Option.kpd");
    auto properties=richonline_property_resources(emp,price);
    auto stocks=richonline_stock_map(emp);
    const auto stock_resources=load_richonline_stock_resources(root);
    for(const auto index:stocks.configurations)
        if(index>=stock_resources.definitions.size()) throw CodecError("richonline_classic_stock_missing");
    auto resources=original_map_resources(std::move(emp),price);
    const auto equipment=RichonlineCombatModifierResources::load(root);
    const RichonlineInitialCash cash(root);
    auto peers=room.participants;
    std::sort(peers.begin(),peers.end(),[](const auto& a,const auto& b){return a.slot<b.slot;});
    std::vector<RichonlineRoomBoardPlayer> supplied;
    std::vector<RichonlineClassicPlayer> ordered;
    std::set<std::uint64_t> used;
    for(const auto& peer:peers) {
        const auto player=std::find_if(players.begin(),players.end(),[&](const auto& p){return p.connection==peer.connection;});
        if(player==players.end() || !used.insert(peer.connection).second || player->identity<0 ||
            static_cast<std::uint32_t>(player->identity)!=peer.actor)
            throw CodecError("richonline_classic_profile_mismatch");
        equipment.validate_supported_equipment(player->equipment);
        supplied.push_back({peer.connection,{player->identity,0,0,player->skills,player->opaque_trailing},
            {cash.apply(resources.human_funds.cash,player->equipment),resources.human_funds.deposit,resources.human_funds.tickets}});
        ordered.push_back(*player);
    }
    RichonlineBoardSnapshot snapshot{header.game_server_id,calendar,resources.scale,{}};
    // 先认证全部身份、技能和资金，再消费随机源，拒绝请求不产生部分会话。
    static_cast<void>(build_richonline_room_boards(room,header,snapshot,supplied));
    const auto spawns=choose_richonline_map_player_spawns(topology,spawn_policy,capacity,random);
    for(std::size_t i=0;i<supplied.size();++i) {
        supplied[i].participant.position=spawns[i].position;
        supplied[i].participant.direction=spawns[i].direction;
    }
    auto recipients=build_richonline_room_boards(room,std::move(header),std::move(snapshot),supplied);
    return {room,name,wait,months,pawn,category,std::move(topology),std::move(properties),std::move(stocks),
        std::move(resources.card_weights),std::move(resources.pool_a_ids),std::move(resources.pool_b_ids),
        std::move(recipients),std::move(ordered)};
}
}
