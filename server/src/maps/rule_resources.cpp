#include "richonline_map_rules.hpp"
#include "richonline_map_package.hpp"
#include "original_options.hpp"

#include <algorithm>
#include <bit>
#include <queue>
#include <set>
#include <utility>

namespace richnet {
namespace {
std::int32_t integer(View bytes,std::size_t offset) {
    if (offset>bytes.size() || bytes.size()-offset<4)
        throw CodecError("richonline_map_rules_tail_truncated");
    return std::bit_cast<std::int32_t>(read_le(bytes.subspan(offset,4)));
}
std::int16_t coordinate(const OriginalEmp& emp,std::int32_t x,std::int32_t y) {
    if (x<0 || y<0 || static_cast<std::uint32_t>(x)>=emp.width || static_cast<std::uint32_t>(y)>=emp.height)
        throw CodecError("richonline_map_rules_coordinate_invalid");
    return static_cast<std::int16_t>(static_cast<std::uint32_t>(y)*emp.width+static_cast<std::uint32_t>(x));
}
}
RichonlineMapStaticRule richonline_map_static_rule(const RichonlineRoadCell& cell) {
    const bool property=cell.property_ref!=-1;
    switch(cell.static_type) {
    case -1: return {RichonlineMapStaticEffect::none,false,false,property};
    case 5: case 6: case 7: return {RichonlineMapStaticEffect::tickets,false,false,property};
    case 8: case 41: case 42: case 43:
        return {RichonlineMapStaticEffect::card_reward,true,false,property};
    case 51: case 52: case 53: case 54:
        return {RichonlineMapStaticEffect::pending_server_reward,true,false,property};
    case 1: case 55: case 56: case 58: case 59: case 60: case 62: case 68: case 69: case 70:
        return {RichonlineMapStaticEffect::chance_event,true,true,property};
    case 10: return {RichonlineMapStaticEffect::shop,true,true,property};
    case 28: case 61: return {RichonlineMapStaticEffect::paired_portal,false,false,property};
    case 57: return {RichonlineMapStaticEffect::local_vendor,false,false,property};
    // 7C54B0 has no active static branch for these plot-road sprite families.
    // 7C6640 then queries road.property_ref via612B69/692260.
    case 33: case 34: case 35: case 36: case 37: case 38: case 39: case 40:
    case 44: case 45: case 46: case 47:
        return {RichonlineMapStaticEffect::none,false,false,property};
    default: return {RichonlineMapStaticEffect::unsupported,false,false,property};
    }
}
std::array<RichonlineMapSpawnChoice,2> choose_richonline_map_conservative_spawns(
    const RichonlineRoadTopology& topology) {
    return choose_richonline_map_spawns(topology,RichonlineMapSpawnPolicy::all_candidates_connected);
}
std::array<RichonlineMapSpawnChoice,2> choose_richonline_map_spawns(
    const RichonlineRoadTopology& topology,RichonlineMapSpawnPolicy policy) {
    if(policy!=RichonlineMapSpawnPolicy::all_candidates_connected &&
        policy!=RichonlineMapSpawnPolicy::largest_adjacent_component)
        throw CodecError("richonline_map_rules_spawn_policy_invalid");
    std::vector<bool> selected(topology.cells().size(),true);
    if(policy==RichonlineMapSpawnPolicy::largest_adjacent_component) {
        std::vector<bool> seen(topology.cells().size());
        std::vector<std::int16_t> largest;
        // Ascending cell order gives a deterministic lowest-position tie break.
        for(const auto& cell:topology.cells()) {
            if(!cell.walkable || seen[static_cast<std::size_t>(cell.position)]) continue;
            std::vector<std::int16_t> component{cell.position};
            seen[static_cast<std::size_t>(cell.position)]=true;
            for(std::size_t index=0;index<component.size();++index)
                for(const auto next:topology.cell(component[index]).neighbors)
                    if(next && !seen[static_cast<std::size_t>(*next)]) {
                        seen[static_cast<std::size_t>(*next)]=true;
                        component.push_back(*next);
                    }
            if(component.size()>largest.size()) largest=std::move(component);
        }
        std::fill(selected.begin(),selected.end(),false);
        for(const auto position:largest) selected[static_cast<std::size_t>(position)]=true;
    }
    std::vector<RichonlineMapSpawnChoice> candidates;
    for(const auto& cell:topology.cells()) {
        if(!cell.walkable || !selected[static_cast<std::size_t>(cell.position)]) continue;
        for(std::uint8_t direction=0;direction<4;++direction)
            if(cell.neighbors[direction] && cell.neighbors[(direction+2U)%4U]) {
                candidates.push_back({cell.position,direction}); break;
            }
    }
    if(candidates.size()<2) throw CodecError("richonline_map_rules_spawn_candidates_missing");
    std::vector<std::int32_t> distances(topology.cells().size(),-1);
    std::queue<std::int16_t> pending;
    pending.push(candidates.front().position); distances[static_cast<std::size_t>(pending.front())]=0;
    while(!pending.empty()) {
        const auto position=pending.front(); pending.pop();
        for(const auto next:topology.cell(position).neighbors)
            if(next && distances[static_cast<std::size_t>(*next)]<0) {
                distances[static_cast<std::size_t>(*next)]=distances[static_cast<std::size_t>(position)]+1;
                pending.push(*next);
            }
    }
    auto farthest=candidates.front();
    for(const auto& candidate:candidates) {
        if(distances[static_cast<std::size_t>(candidate.position)]<0)
            throw CodecError("richonline_map_rules_spawn_graph_disconnected");
        if(distances[static_cast<std::size_t>(candidate.position)]>distances[static_cast<std::size_t>(farthest.position)])
            farthest=candidate;
    }
    return {candidates.front(),farthest};
}
RichonlineMapRuleResources load_richonline_map_rule_resources(const std::filesystem::path& root,
    const RichonlineMapPackage& package,std::uint32_t category) {
    const auto stage=package.load_stage(root,category);
    const auto emp=load_original_emp(root/"Map"/std::filesystem::path(package.map_name));
    return richonline_map_rule_resources(stage,emp,package.resource_rules,
        load_original_price_base(root/"Data"/"Option.kpd"));
}
RichonlineMapRuleResources richonline_map_rule_resources(const RichonlineBossStage& stage,
    const OriginalEmp& emp,const RichonlineMapRuleSpecification& specification,std::int32_t price_base) {
    if(stage.width!=emp.width || stage.height!=emp.height || stage.signature!=emp.signature)
        throw CodecError("richonline_map_rules_stage_metadata_mismatch");
    if(emp.tail_offset>emp.payload.size()) throw CodecError("richonline_map_rules_tail_truncated");
    auto topology=richonline_road_topology(emp);
    auto properties=richonline_property_resources(emp,price_base);
    RichonlineMapRuleResources result{stage,std::move(topology),std::move(properties),{},{},{},{},{},{},{},{},{},{},{},0,{},{}};
    std::set<std::int8_t> observed;
    for(const auto& cell:result.topology.cells()) {
        if(!cell.walkable) continue;
        ++result.static_counts[cell.static_type]; ++result.terrain_counts[cell.terrain_type]; observed.insert(cell.static_type);
    }
    const std::set<std::int8_t> expected(specification.expected_static_types.begin(),
        specification.expected_static_types.end());
    if(expected.empty() || expected.size()!=specification.expected_static_types.size() || observed!=expected)
        throw CodecError("richonline_map_rules_static_boundary_mismatch");
    const auto tail=View(emp.payload).subspan(emp.tail_offset);
    for(std::size_t i=0;i<result.source_prelude.size();++i) result.source_prelude[i]=integer(tail,4U*i);
    for(std::size_t i=0;i<result.portals.size();++i) {
        const auto type=static_cast<std::int8_t>(i==0 ? 28 : 61);
        const auto count=result.static_counts.contains(type) ? result.static_counts.at(type) : 0U;
        if(count==0) continue;
        if(count!=2) throw CodecError("richonline_map_rules_portal_pair_invalid");
        const auto offset=i==0 ? 64U : 80U;
        const std::array pair{coordinate(emp,integer(tail,offset),integer(tail,offset+4U)),
            coordinate(emp,integer(tail,offset+8U),integer(tail,offset+12U))};
        if(pair[0]==pair[1]) throw CodecError("richonline_map_rules_portal_pair_invalid");
        for(const auto position:pair) {
            const auto& cell=result.topology.cell(position);
            if(!cell.walkable || cell.static_type!=type) throw CodecError("richonline_map_rules_portal_pair_invalid");
        }
        result.portals[i]=pair;
    }
    std::size_t cursor=120;
    const auto count_array=[&](std::size_t stride) {
        const auto value=integer(tail,cursor); cursor+=4;
        if(value<0 || cursor>tail.size() || static_cast<std::size_t>(value)>(tail.size()-cursor)/stride)
            throw CodecError("richonline_map_rules_tail_array_invalid");
        return static_cast<std::size_t>(value);
    };
    const auto source_count=count_array(4);
    for(std::size_t i=0;i<source_count;++i) {
        result.source_dword_array.push_back(read_le(tail.subspan(cursor,4))); cursor+=4;
    }
    const auto card_count=count_array(8);
    std::set<std::int16_t> cards;
    for(std::size_t i=0;i<card_count;++i) {
        const auto id=integer(tail,cursor),weight=integer(tail,cursor+4); cursor+=8;
        if(id<1 || id>32767 || weight<0 || !cards.insert(static_cast<std::int16_t>(id)).second)
            throw CodecError("richonline_map_rules_card_array_invalid");
        result.card_weights.push_back({static_cast<std::int16_t>(id),static_cast<std::uint32_t>(weight)});
    }
    if(card_count!=0) for(auto* pool:{&result.pool_a_ids,&result.pool_b_ids}) {
        const auto size=count_array(4);
        std::set<std::int16_t> unique;
        for(std::size_t i=0;i<size;++i) {
            const auto id=integer(tail,cursor); cursor+=4;
            if(id<1 || id>32767 || !cards.contains(static_cast<std::int16_t>(id)) ||
                !unique.insert(static_cast<std::int16_t>(id)).second)
                throw CodecError("richonline_map_rules_card_pool_invalid");
            pool->push_back(static_cast<std::int16_t>(id));
        }
    }
    // The two independently counted arrays precede the11-DWORD postlude.
    // Skipping them would misinterpret their lengths as NPC configuration.
    for(auto& array:result.source_extra_arrays) {
        const auto size=count_array(4);
        for(std::size_t i=0;i<size;++i) {
            array.push_back(read_le(tail.subspan(cursor,4))); cursor+=4;
        }
    }
    for(auto& value:result.source_postlude) { value=integer(tail,cursor); cursor+=4; }
    const auto count=integer(tail,cursor); cursor+=4;
    if(count<0 || cursor>tail.size() || static_cast<std::size_t>(count)>(tail.size()-cursor)/8U)
        throw CodecError("richonline_map_rules_initial_npcs_invalid");
    std::set<std::int16_t> npc_tiles;
    for(std::int32_t index=0;index<count;++index) {
        const auto position=integer(tail,cursor); cursor+=4;
        const auto value=read_le(tail.subspan(cursor,4)); cursor+=4;
        if(position<0 || static_cast<std::uint32_t>(position)>=emp.width*emp.height ||
            !result.topology.cell(static_cast<std::int16_t>(position)).walkable ||
            !npc_tiles.insert(static_cast<std::int16_t>(position)).second)
            throw CodecError("richonline_map_rules_initial_npcs_invalid");
        // Exact NEW7DF010 call604D66(position,29,-1,-1), not zero padding.
        result.initial_npcs.push_back({static_cast<std::int16_t>(position),29,-1,-1,value});
    }
    result.parsed_tail_bytes=cursor;
    try { result.conservative_spawns=choose_richonline_map_spawns(result.topology,specification.spawn_policy); }
    catch(const CodecError& error) {
        const std::string_view code=error.what();
        if(code!="richonline_map_rules_spawn_graph_disconnected" &&
            code!="richonline_map_rules_spawn_candidates_missing") throw;
        result.conservative_spawn_error=std::string(code);
    }
    return result;
}
}
