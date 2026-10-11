#include "richonline_combat_world.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <set>

namespace richnet {
namespace {
constexpr auto maximum=std::numeric_limits<std::int32_t>::max();
std::string decoded(const std::filesystem::path& file) {
    const auto bytes=load_original_kpd(file,8U*1024U*1024U);
    return {reinterpret_cast<const char*>(bytes.data()),bytes.size()};
}
std::int32_t add(std::int32_t first,std::int32_t second) {
    const auto sum=static_cast<std::int64_t>(first)+second;
    if(first<0 || second<0 || sum>maximum) throw CodecError("richonline_combat_world_attribute_overflow");
    return static_cast<std::int32_t>(sum);
}
std::optional<std::uint8_t> building_level(std::optional<std::uint32_t> source,std::uint8_t activation_level,
    const RichonlineCombatSessionView& state) {
    if(!source) return {};
    const auto found=std::find_if(state.buildings.begin(),state.buildings.end(),[&](const auto& building) {
        return building.property==*source;
    });
    if(found==state.buildings.end() || activation_level==0 || activation_level>7)
        throw CodecError("richonline_combat_world_active_building_stale");
    return activation_level;
}
std::uint32_t distance(std::int16_t first,std::int16_t second,std::uint32_t width) {
    const auto ax=static_cast<std::int32_t>(first)%static_cast<std::int32_t>(width);
    const auto ay=static_cast<std::int32_t>(first)/static_cast<std::int32_t>(width);
    const auto bx=static_cast<std::int32_t>(second)%static_cast<std::int32_t>(width);
    const auto by=static_cast<std::int32_t>(second)/static_cast<std::int32_t>(width);
    return static_cast<std::uint32_t>(std::abs(ax-bx)+std::abs(ay-by));
}
bool within_range(std::int16_t origin,std::int16_t target,const RichonlineRoadTopology& topology,
    const RichonlineCombatRangePolicy& range) {
    if(range.name=="server_manhattan_tile_radius")
        return distance(origin,target,topology.width())<=range.manhattan_radius;
    // NEW7E6DA0 intersects64x48 tile bounds with a pixel rectangle. Camera
    // coordinates are not uploaded; this server rectangle follows the BOSS.
    const auto map_width=static_cast<std::int32_t>(topology.width())*64;
    const auto map_height=static_cast<std::int32_t>(topology.height())*48;
    const auto width=std::min<std::int32_t>(range.viewport_width,map_width);
    const auto height=std::min<std::int32_t>(range.viewport_height,map_height);
    const auto columns=static_cast<std::int32_t>(topology.width());
    const auto left=std::clamp((origin%columns)*64+32-width/2,0,map_width-width);
    const auto top=std::clamp((origin/columns)*48+24-height/2,0,map_height-height);
    const auto x=(target%columns)*64;
    const auto y=(target/columns)*48;
    return x<left+width && x+64>left && y<top+height && y+48>top;
}
bool placement_occupied(std::int16_t position,const RichonlineCombatSessionView& state) {
    return std::ranges::any_of(state.actors,[&](const auto& actor) {
        return actor && actor->active && actor->placement_present &&
            (actor->position==position || actor->pet_position==position);
    });
}
}
RichonlineCombatWorld::ResolvedTerms richonline_possession_combat_terms(
    const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&) {
    if(actor.status.possession) switch(*actor.status.possession) {
    case 0: // NEW694C90: defense0.5, resolved by the damage calculator.
    case 1: // NEW694CC0: defense1.5.
    case 2: // NEW693D10: attack0.5.
    case 3: // NEW701530: attack1.5.
    case 4:
    case 6:
    case 7: // None of those equality predicates match this possession.
        break;
    default:throw CodecError("richonline_combat_world_possession_extension_required");
    }
    RichonlineCombatWorld::ResolvedTerms result{{},{},0,0};
    if(actor.status.possession_strength1740>0) {
        if(!std::isfinite(actor.status.possession_multiplier1744))
            throw CodecError("richonline_combat_modifier_invalid");
        result.attack.possession_amplification=actor.status.possession_multiplier1744;
        result.defense.possession_amplification=actor.status.possession_multiplier1744;
    }
    return result;
}
RichonlineCombatWorld::ResolvedTerms richonline_unamplified_possession_combat_terms(
    const RichonlineCombatActorView& actor,const RichonlineCombatSessionView& state) {
    if(actor.status.possession_strength1740>0)
        throw CodecError("richonline_combat_world_possession_extension_required");
    return richonline_possession_combat_terms(actor,state);
}
RichonlineCombatWorldFactoryResult make_richonline_combat_world(const std::filesystem::path& resources,
    const RichonlineRoadTopology& topology,const RichonlineBossStage& stage,
    const std::array<std::uint32_t,32>& human_equipment,const RichonlineMapCombatPolicy& map,
    std::shared_ptr<RichonlineBossProperty> property,RichonlineCombatWorldPolicy policy) {
    if(!property || topology.width()!=stage.width || topology.height()!=stage.height ||
        topology.width()==0 || topology.height()==0 || topology.width()>32768 || topology.height()>32768 ||
        static_cast<std::uint64_t>(topology.width())*topology.height()>32768)
        throw CodecError("richonline_combat_world_topology_invalid");
    if(map.attempts!=4 || map.idle_weight!=80 || map.mine_weight!=10 || map.projectile_weight!=10 ||
        !map.targets_within_visibility || !map.allow_self_target || !map.attacks_require_actionable_status ||
        map.consume_boss_inventory || map.uniform_projectiles.empty())
        throw CodecError("richonline_combat_world_map_policy_unimplemented");
    const bool radial=policy.range.name=="server_manhattan_tile_radius" &&
        policy.range.manhattan_radius>0 && policy.range.manhattan_radius<=64;
    const bool viewport=policy.range.name=="server_boss_centered_viewport" &&
        policy.range.viewport_width>=64 && policy.range.viewport_width<=4096 &&
        policy.range.viewport_height>=48 && policy.range.viewport_height<=4096 &&
        policy.range.projectile_candidates==RichonlineProjectileCandidates::road_tiles;
    if((!radial && !viewport) || !policy.mine_landing_supported)
        throw CodecError("richonline_combat_world_range_policy_invalid");
    if(policy.range.projectile_candidates!=RichonlineProjectileCandidates::road_tiles &&
        policy.range.projectile_candidates!=RichonlineProjectileCandidates::all_map_tiles)
        throw CodecError("richonline_combat_world_candidates_invalid");
    const auto modifiers=std::make_shared<const RichonlineCombatModifierResources>(
        RichonlineCombatModifierResources::load(resources));
    const std::array equipment{human_equipment,RichonlineCombatModifierResources::boss_equipment(stage)};
    if(!policy.extra_terms || !policy.capabilities) {
        std::set<std::uint16_t> neutral;
        for(const auto id:policy.neutral_human_equipment)
            if(id==0 || id>4095 || !neutral.insert(id).second)
                throw CodecError("richonline_combat_world_neutral_equipment_invalid");
        modifiers->validate_supported_equipment(human_equipment);
        // Pet/vehicle/land/deity/dice/move items can carry additional capability
        // rules. The current closed initial actor model does not own those rules.
        for(std::size_t slot=0;slot<6;++slot)
            if((equipment[1][slot]&0xfffU)!=0)
                throw CodecError("richonline_combat_world_boss_equipment_extension_required");
    }
    // 开局校验BOSS资源；生产会话另外提供与客户端回合入口一致的装备缓存。
    (void)modifiers->equipment(equipment[1],stage.boss.base_cash);
    RichonlineCombatWorldFactoryResult result;
    result.target_policy=policy.range.name;
    result.world.width=static_cast<std::uint16_t>(topology.width());
    result.world.height=static_cast<std::uint16_t>(topology.height());
    for(const auto& cell:topology.cells()) if(cell.walkable)
        result.world.missile_base_roads.push_back(cell.position);
    result.world.resources=RichonlineCombatResources::parse(decoded(resources/"Data"/"Prop.kpd"),
        decoded(resources/"Data"/"Npc.kpd"),decoded(resources/"Data"/"GValue.kpd"));
    result.world.step=[topology](std::int16_t position,std::uint8_t direction) {
        if(direction>=4) throw CodecError("richonline_combat_world_direction_invalid");
        const auto& cell=topology.cell(position);
        return cell.walkable?cell.neighbors[direction]:std::optional<std::int16_t>{};
    };
    result.world.targets=[topology,range=policy.range,mine_supported=policy.mine_landing_supported]
        (std::uint8_t actor,RichonlineCombatEffect effect,const RichonlineCombatSessionView& state) {
        if(actor>=state.actors.size() || !state.actors[actor]) throw CodecError("richonline_combat_world_actor_invalid");
        const auto origin=state.actors[actor]->position;
        if(!topology.cell(origin).walkable) throw CodecError("richonline_combat_world_origin_invalid");
        std::vector<std::int16_t> targets;
        for(const auto& cell:topology.cells()) {
            if(!within_range(origin,cell.position,topology,range)) continue;
            if(effect==RichonlineCombatEffect::mine) {
                if(!cell.walkable || placement_occupied(cell.position,state) || !mine_supported(cell.position,state)) continue;
            } else if(effect!=RichonlineCombatEffect::missile && effect!=RichonlineCombatEffect::nuclear &&
                effect!=RichonlineCombatEffect::safe_nuclear) throw CodecError("richonline_combat_world_effect_invalid");
            else if(range.projectile_candidates==RichonlineProjectileCandidates::road_tiles && !cell.walkable) continue;
            targets.push_back(cell.position);
        }
        return targets;
    };
    result.world.card_targets=[topology,mine_supported=policy.mine_landing_supported]
        (std::uint8_t actor,RichonlineCombatEffect effect,const RichonlineCombatSessionView& state) {
        if(actor!=0 || !state.actors[actor]) throw CodecError("richonline_combat_world_human_card_actor_invalid");
        const auto origin=state.actors[actor]->position;
        if(!topology.cell(origin).walkable) throw CodecError("richonline_combat_world_origin_invalid");
        std::vector<std::int16_t> targets;
        for(const auto& cell:topology.cells()) {
            if(effect==RichonlineCombatEffect::mine) {
                if(!cell.walkable || placement_occupied(cell.position,state) || !mine_supported(cell.position,state)) continue;
            } else if(effect!=RichonlineCombatEffect::missile && effect!=RichonlineCombatEffect::nuclear &&
                effect!=RichonlineCombatEffect::safe_nuclear)
                throw CodecError("richonline_combat_world_human_card_effect_invalid");
            // NEW Prop1046 permits whole-map targeting. This includes property
            // and empty tiles and is independent of BOSS authorization range.
            targets.push_back(cell.position);
        }
        return targets;
    };
    result.world.detonation_roots=[topology,range=policy.range]
        (std::uint8_t actor,const RichonlineCombatSessionView& state) {
        if(actor>=state.actors.size() || !state.actors[actor])
            throw CodecError("richonline_detonation_actor_invalid");
        std::vector<std::int16_t> roots;
        for(const auto& mine:state.mines.mines)
            if(within_range(state.actors[actor]->position,mine.position,topology,range)) roots.push_back(mine.position);
        return roots;
    };
    result.world.building=[property=std::move(property)](const RichonlineCombatBuildingView& before,
        RichonlineBossBlastBuildingEffect effect) { return property->combat_building_effect(before,effect); };
    result.world.resolve_terms=[modifiers,equipment,extra=policy.extra_terms,cached=policy.equipment_terms]
        (const RichonlineCombatActorView& actor,const RichonlineCombatSessionView& state) {
        if(actor.slot>=equipment.size()) throw CodecError("richonline_combat_world_actor_invalid");
        auto terms=extra?extra(actor,state):richonline_possession_combat_terms(actor,state);
        if(terms.attack.building_multiplier!=1.0F || terms.defense.building_multiplier!=1.0F)
            throw CodecError("richonline_combat_world_building_term_duplicated");
        const auto attributes=cached ? cached(actor.slot) :
            modifiers->equipment(equipment[actor.slot],actor.funds.funds.cash);
        terms.flat_attack=add(terms.flat_attack,attributes.flat_attack);
        terms.flat_defense=add(terms.flat_defense,attributes.flat_defense);
        terms.attack.equipment_percentage=add(terms.attack.equipment_percentage,attributes.attack_percentage);
        terms.defense.equipment_percentage=add(terms.defense.equipment_percentage,attributes.defense_percentage);
        terms.attack.building_multiplier=modifiers->attack_building(building_level(actor.attack_building_source,actor.attack_building_level,state));
        terms.defense.building_multiplier=modifiers->defense_building(building_level(actor.defense_building_source,actor.defense_building_level,state));
        return terms;
    };
    if(policy.helmet) result.world.helmet=std::move(policy.helmet);
    else {
        const auto limits=RichonlinePropUseLimits::load(resources);
        const auto cards=RichonlineChanceResources::load(resources);
        const bool eligible=cards.automatic_card_eligible(stage.map_name,1076);
        result.world.helmet=[limits,eligible,mode=stage.mode]
            (const RichonlineCombatActorView& actor,const RichonlineCombatSessionView&) {
            return prepare_richonline_safety_helmet(actor.inventory,actor.status.safety_helmet_uses,mode,limits,eligible);
        };
    }
    result.capabilities=policy.capabilities?std::move(policy.capabilities):
        [](std::uint8_t actor,const RichonlineActorStatus&,bool active) {
            if(actor>=2) throw CodecError("richonline_combat_world_actor_invalid");
            // Named closed_initial_status_policy: current owner implements no
            // hospital/prison timers or combat immunity equipment. Status
            // sleepwalk/frozen action gates are still handled by the coordinator.
            return RichonlineCombatCapabilities{active,false,false,false,true};
        };
    std::set<RichonlineMapProjectile> seen;
    result.boss.projectiles.clear();
    for(const auto projectile:map.uniform_projectiles) {
        if(!seen.insert(projectile).second) throw CodecError("richonline_combat_world_projectile_duplicate");
        switch(projectile) {
        case RichonlineMapProjectile::missile:result.boss.projectiles.push_back(RichonlineCombatEffect::missile);break;
        case RichonlineMapProjectile::nuclear:result.boss.projectiles.push_back(RichonlineCombatEffect::nuclear);break;
        case RichonlineMapProjectile::safe_nuclear:result.boss.projectiles.push_back(RichonlineCombatEffect::safe_nuclear);break;
        default:throw CodecError("richonline_combat_world_projectile_invalid");
        }
    }
    if(auto script=LuaServer::create()) {
        result.boss.select_attack=[script,map_name=stage.map_name,allowed=result.boss.projectiles]
            (std::uint8_t roll,const std::function<std::size_t(std::size_t)>& random)->std::optional<RichonlineCombatEffect> {
            auto projectiles=LuaValue::array();
            for(const auto effect:allowed) projectiles.push_back(static_cast<int>(effect));
            const LuaBindings api{{"random",[&](const LuaValue& args) {
                const auto upper=args.at("upper").get<std::int64_t>();
                if(upper<1 || upper>32768 || !random) throw CodecError("lua_boss_random_invalid");
                const auto selected=random(static_cast<std::size_t>(upper));
                if(selected>=static_cast<std::size_t>(upper)) throw CodecError("lua_boss_random_out_of_range");
                return LuaValue(selected+1);
            }}};
            const auto selected=script->call("boss.attack",{{"map",map_name},{"roll",roll},
                {"projectiles",projectiles},{"mine",static_cast<int>(RichonlineCombatEffect::mine)}},api);
            if(selected.is_null()) return {};
            const auto code=selected.get<int>();
            if(code==static_cast<int>(RichonlineCombatEffect::mine)) return RichonlineCombatEffect::mine;
            for(const auto effect:allowed) if(code==static_cast<int>(effect)) return effect;
            throw CodecError("lua_boss_attack_invalid");
        };
    }
    return result;
}
}
