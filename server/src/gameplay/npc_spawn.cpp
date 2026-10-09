#include "richonline_npc_spawn.hpp"
#include <algorithm>
#include <limits>
#include <set>

namespace richnet {
namespace {
bool population(std::int8_t npc) { return (npc>=0 && npc<=7) || npc==9; }
void valid_object(RichonlineGroundObject object) {
    if(object.npc<0 || object.npc>32) throw CodecError("richonline_ground_npc_out_of_range");
}
std::size_t count(const RichonlineGroundMap& map) {
    return static_cast<std::size_t>(std::count_if(map.begin(),map.end(),[](const auto& p) {return population(p.second.npc);}));
}
class SpawnBatch {
public:
    RichonlineGroundMap after;
    std::mt19937 random;
    RichonlineNpcSpawnResult result;
    SpawnBatch(const RichonlineGroundObjects& ground,const RichonlineGroundSnapshot& before,
        const std::mt19937& source,std::uint16_t game,const RichonlineNpcSpawnPolicy& policy)
        :after(before.objects),random(source),game_(game),policy_(policy) {
        for(const auto position:ground.positions()) if(!after.contains(position)) free_.push_back(position);
    }
    bool spawn(bool chest) {
        if(free_.empty() || count(after)>=policy_.maximum_objects) return false;
        auto candidates=policy_.god_pool;
        for(const auto& [position,object]:after) {
            (void)position;
            std::erase(candidates,object.npc);
        }
        if(!chest && candidates.empty()) return false;
        const auto choose=[&](std::size_t n) { return std::uniform_int_distribution<std::size_t>(0,n-1)(random); };
        const auto free_index=choose(free_.size()); const auto position=free_[free_index];
        const RichonlineGroundObject object=chest
            ? RichonlineGroundObject{9,policy_.chest_byte7,policy_.chest_byte8}
            : RichonlineGroundObject{candidates[choose(candidates.size())],policy_.god_byte7,policy_.god_byte8};
        result.messages.push_back(encode_richonline_npc_spawn401c(game_,position,object));
        after.emplace(position,object); free_.erase(free_.begin()+static_cast<std::ptrdiff_t>(free_index));
        return true;
    }
    bool spawn_any() {
        if(!policy_.refresh_chests) return spawn(false);
        // Equal choice of chest versus deity category is explicit emulator policy.
        if(std::uniform_int_distribution<int>(0,1)(random)==0 && spawn(false)) return true;
        return spawn(true);
    }
private:
    std::vector<std::int16_t> free_;
    std::uint16_t game_;
    const RichonlineNpcSpawnPolicy& policy_;
};
}
RichonlineGroundObjects::RichonlineGroundObjects(std::vector<std::int16_t> positions):positions_(std::move(positions)) {
    std::sort(positions_.begin(),positions_.end());
    if((!positions_.empty() && positions_.front()<0) ||
        std::adjacent_find(positions_.begin(),positions_.end())!=positions_.end())
        throw CodecError("richonline_ground_positions_invalid");
}
RichonlineGroundSnapshot RichonlineGroundObjects::snapshot() const { return {objects_,revision_}; }
RichonlineGroundObjects::Prepared RichonlineGroundObjects::prepare(
    const RichonlineGroundSnapshot& before,const RichonlineGroundMap& after) const {
    if(before.revision!=revision_ || before.objects!=objects_) throw CodecError("richonline_ground_stale");
    for(const auto& [position,object]:after) {
        if(!std::binary_search(positions_.begin(),positions_.end(),position)) throw CodecError("richonline_ground_position_invalid");
        valid_object(object);
    }
    if(after!=objects_ && revision_==std::numeric_limits<std::uint64_t>::max())
        throw CodecError("richonline_ground_revision_overflow");
    Prepared result; result.expected_=before; result.after_=after; return result;
}
bool RichonlineGroundObjects::matches(const Prepared& prepared) const noexcept {
    return !prepared.committed_ && prepared.expected_.revision==revision_ && prepared.expected_.objects==objects_;
}
bool RichonlineGroundObjects::commit_prepared(Prepared& prepared) noexcept {
    if(!matches(prepared)) return false;
    if(objects_!=prepared.after_) { objects_.swap(prepared.after_); ++revision_; }
    prepared.committed_=true; return true;
}
bool RichonlineGroundObjects::commit(const RichonlineGroundSnapshot& before,const RichonlineGroundMap& after) {
    if(before.revision!=revision_ || before.objects!=objects_) return false;
    for(const auto& [position,object]:after) {
        if(!std::binary_search(positions_.begin(),positions_.end(),position)) throw CodecError("richonline_ground_position_invalid");
        valid_object(object);
    }
    if(after==objects_) return true;
    if(revision_==std::numeric_limits<std::uint64_t>::max()) throw CodecError("richonline_ground_revision_overflow");
    auto prepared=after; objects_.swap(prepared); ++revision_; return true;
}
void RichonlineGroundObjects::place(std::int16_t position,RichonlineGroundObject object) {
    const auto before=snapshot(); auto after=before.objects;
    if(!after.emplace(position,object).second) throw CodecError("richonline_ground_position_occupied");
    if(!commit(before,after)) throw CodecError("richonline_ground_stale");
}
bool RichonlineGroundObjects::consume(std::int16_t position,RichonlineGroundObject expected) {
    const auto before=snapshot(); auto after=before.objects; const auto found=after.find(position);
    if(found==after.end() || found->second!=expected) return false;
    after.erase(found); return commit(before,after);
}
Bytes encode_richonline_npc_spawn401c(std::uint16_t game,std::int16_t position,RichonlineGroundObject object) {
    valid_object(object);
    if(position<0 || object.npc==26) throw CodecError("richonline_npc_spawn_special_or_invalid");
    Bytes bytes; append_le(bytes,0x401c,2); append_le(bytes,game,2);
    append_le(bytes,static_cast<std::uint16_t>(position),2);
    bytes.push_back(static_cast<std::uint8_t>(object.npc)); bytes.push_back(object.byte7); bytes.push_back(object.byte8);
    return bytes;
}
RichonlineNpcSpawnPolicy RichonlineNpcSpawnPolicy::user_requested(std::uint8_t g7,std::uint8_t g8,std::uint8_t c7,std::uint8_t c8) {
    return {4,1,2,5,3,{0,1,2,3,4,5,6,7},g7,g8,c7,c8};
}
RichonlineNpcSpawner::RichonlineNpcSpawner(std::uint16_t game,RichonlineNpcSpawnPolicy policy,std::uint32_t seed)
    :game_(game),policy_(std::move(policy)),random_(seed) {
    const std::set<std::int8_t> unique(policy_.god_pool.begin(),policy_.god_pool.end());
    if(policy_.maximum_objects==0 || policy_.maximum_objects>5 || policy_.minimum_objects>policy_.maximum_objects ||
        policy_.initial_gods>policy_.maximum_objects || policy_.initial_chests>policy_.maximum_objects-policy_.initial_gods ||
        (!policy_.refresh_chests && policy_.initial_chests!=0) ||
        policy_.refresh_every_rounds==0 || policy_.god_pool.empty() || unique.size()!=policy_.god_pool.size() ||
        *unique.begin()<0 || *unique.rbegin()>7 || policy_.initial_gods>unique.size())
        throw CodecError("richonline_npc_spawn_policy_invalid");
}
RichonlineNpcSpawnResult RichonlineNpcSpawner::initialize(RichonlineGroundObjects& ground) {
    if(initialized_) throw CodecError("richonline_npc_spawn_already_initialized");
    const auto before=ground.snapshot();
    if(count(before.objects)!=0) throw CodecError("richonline_npc_spawn_initial_population_present");
    SpawnBatch batch(ground,before,random_,game_,policy_);
    for(std::size_t i=0;i<policy_.initial_gods;++i) if(!batch.spawn(false)) ++batch.result.unmet_target;
    for(std::size_t i=0;i<policy_.initial_chests;++i) if(!batch.spawn(true)) ++batch.result.unmet_target;
    if(!ground.commit(before,batch.after)) throw CodecError("richonline_ground_stale");
    random_=batch.random; initialized_=true; return std::move(batch.result);
}
RichonlineNpcSpawnResult RichonlineNpcSpawner::replenish_minimum(RichonlineGroundObjects& ground) {
    if(!initialized_) throw CodecError("richonline_npc_spawn_not_initialized");
    const auto before=ground.snapshot();
    if(count(before.objects)>policy_.maximum_objects) throw CodecError("richonline_npc_spawn_population_exceeds_policy");
    SpawnBatch batch(ground,before,random_,game_,policy_);
    while(count(batch.after)<policy_.minimum_objects) {
        if(!batch.spawn_any()) { batch.result.unmet_target=policy_.minimum_objects-count(batch.after); break; }
    }
    if(!ground.commit(before,batch.after)) throw CodecError("richonline_ground_stale");
    random_=batch.random; return std::move(batch.result);
}
RichonlineNpcSpawnResult RichonlineNpcSpawner::finish_round(RichonlineGroundObjects& ground,std::uint64_t identity) {
    if(!initialized_ || identity==0) throw CodecError("richonline_npc_spawn_round_invalid");
    if(identity==last_round_) return {{},0,true};
    if(last_round_==std::numeric_limits<std::uint64_t>::max() || identity!=last_round_+1)
        throw CodecError("richonline_npc_spawn_round_out_of_order");
    const auto before=ground.snapshot(); const auto existing=count(before.objects);
    if(existing>policy_.maximum_objects) throw CodecError("richonline_npc_spawn_population_exceeds_policy");
    SpawnBatch batch(ground,before,random_,game_,policy_);
    const auto target=std::max(policy_.minimum_objects,std::min(policy_.maximum_objects,
        existing+static_cast<std::size_t>(identity%policy_.refresh_every_rounds==0)));
    while(count(batch.after)<target) {
        if(!batch.spawn_any()) { batch.result.unmet_target=target-count(batch.after); break; }
    }
    if(!ground.commit(before,batch.after)) throw CodecError("richonline_ground_stale");
    random_=batch.random; last_round_=identity; return std::move(batch.result);
}
std::optional<std::uint8_t> plan_richonline_temple_duration(std::uint8_t turns,
    bool extend,std::int32_t days,std::uint8_t maximum) {
    if(!maximum || maximum>127) throw CodecError("richonline_temple_maximum_invalid");
    const auto signed_byte=[](std::uint8_t value) {return value<128 ? static_cast<int>(value) : static_cast<int>(value)-256;};
    if(extend) {
        if(days<=0) return turns;
        const auto added=static_cast<std::uint8_t>(static_cast<std::uint32_t>(turns)+static_cast<std::uint32_t>(days));
        return signed_byte(added)>maximum ? maximum : added;
    }
    if(days<=0) return {};
    const auto reduced=static_cast<std::uint8_t>(static_cast<std::uint32_t>(turns)-static_cast<std::uint32_t>(days)-1U);
    return signed_byte(reduced)>0 ? std::optional{reduced} : std::nullopt;
}
RichonlinePossessionTick tick_richonline_possession(const RichonlinePossessionClock& clock,
    const RichonlineActorStatus& status,std::uint64_t identity) {
    if(identity==0 || clock.npc!=status.possession ||
        (!clock.npc && clock.turns!=0)) throw CodecError("richonline_possession_clock_invalid");
    if(clock.last_actor_turn && identity<*clock.last_actor_turn) throw CodecError("richonline_possession_turn_out_of_order");
    if(clock.last_actor_turn==identity) return {clock,status,{},true};
    RichonlinePossessionTick result{clock,status,{},false}; result.clock.last_actor_turn=identity;
    if(result.clock.npc && (--result.clock.turns==0 || result.clock.turns>127)) {
        result.expired=result.clock.npc; result.clock.npc.reset(); richonline_detach_possession(result.status);
        result.clock.turns=0;
    }
    return result;
}
}
