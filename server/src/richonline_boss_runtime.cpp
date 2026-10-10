#include "richonline_boss_runtime.hpp"
#include "richonline_boss_host.hpp"
#include "richonline_boss_session.hpp"
#include "richonline_team_identity.hpp"
#include "richonline_levels.hpp"
#include "richonline_raw_authority.hpp"
#include "richonline_ground_card_authority.hpp"
#include "richonline_timed_bomb.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <fstream>
#include <limits>
#include <string_view>
#include <utility>

namespace richnet {
namespace {
using Json = nlohmann::json;
constexpr std::string_view scope = "ordinary-movement-unimplemented-landings-rejected";
std::int64_t number(const Json& value,std::int64_t minimum,std::int64_t maximum) {
    if (!value.is_number_integer() || value < minimum || value > maximum)
        throw CodecError("richonline_boss_turn_policy_number_invalid");
    return value.get<std::int64_t>();
}
template<class T,std::size_t N> std::array<T,N> numbers(const Json& value,std::int64_t minimum,std::int64_t maximum) {
    if (!value.is_array() || value.size() != N) throw CodecError("richonline_boss_turn_policy_array_invalid");
    std::array<T,N> result;
    for (std::size_t i = 0; i < N; ++i) result[i] = static_cast<T>(number(value[i],minimum,maximum));
    return result;
}
Bytes tail(const Json& value) {
    if (!value.is_string()) throw CodecError("richonline_boss_turn_policy_tail_invalid");
    const auto text = value.get<std::string>();
    if (text.size()%2 != 0 || text.size() > 520) throw CodecError("richonline_boss_turn_policy_tail_invalid");
    const auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c-'0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c-'a'+10);
        if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c-'A'+10);
        throw CodecError("richonline_boss_turn_policy_tail_invalid");
    };
    Bytes bytes(text.size()/2);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::uint8_t>((nibble(text[2*i]) << 4) | nibble(text[2*i+1]));
    return bytes;
}
struct Policy {
    std::string provenance;
    std::uint8_t opaque_turn7;
    std::array<std::int8_t,2> inactive_ui_dice;
    std::array<std::uint8_t,4> opaque20_23;
    Bytes optional_tail;
};
Policy policy(const Json& value) {
    constexpr std::array names{"provenance","opaque_turn7","inactive_ui_dice","opaque20_23","optional_tail_hex","scope"};
    if (!value.is_object() || value.size() != names.size()) throw CodecError("richonline_boss_turn_policy_fields_invalid");
    for (const auto name : names) if (!value.contains(name)) throw CodecError("richonline_boss_turn_policy_fields_invalid");
    if (value.at("scope") != scope) throw CodecError("richonline_boss_turn_policy_scope_invalid");
    if (!value.at("provenance").is_string()) throw CodecError("richonline_boss_turn_policy_provenance_required");
    auto source = value.at("provenance").get<std::string>();
    if (source.size() < 8 || source.size() > 4096 || source.find('\0') != source.npos)
        throw CodecError("richonline_boss_turn_policy_provenance_required");
    return {std::move(source),static_cast<std::uint8_t>(number(value.at("opaque_turn7"),0,255)),
        numbers<std::int8_t,2>(value.at("inactive_ui_dice"),-128,127),numbers<std::uint8_t,4>(value.at("opaque20_23"),0,255),
        tail(value.at("optional_tail_hex"))};
}
std::optional<RichonlineBossCardPolicy> card_policy(const Json& config) {
    if (!config.contains("richonline_boss_card_policy")) return {};
    const auto& value = config.at("richonline_boss_card_policy");
    constexpr std::array names{"provenance","event_id","card_id","opaque6_7"};
    if (!value.is_object() || value.size() != names.size()) throw CodecError("richonline_boss_card_policy_fields_invalid");
    for (const auto name : names) if (!value.contains(name)) throw CodecError("richonline_boss_card_policy_fields_invalid");
    if (!value.at("provenance").is_string()) throw CodecError("richonline_boss_card_policy_provenance_required");
    const auto source = value.at("provenance").get<std::string>();
    if (source.size() < 8 || source.size() > 4096 || source.find('\0') != source.npos)
        throw CodecError("richonline_boss_card_policy_provenance_required");
    return RichonlineBossCardPolicy{std::string(legacy_richonline_map_package().map_name),static_cast<std::int32_t>(number(value.at("event_id"),0,32767)),
        static_cast<std::int32_t>(number(value.at("card_id"),1,32767)),numbers<std::uint8_t,2>(value.at("opaque6_7"),0,255)};
}
std::optional<RichonlineGameBankWirePolicy> bank_policy(const Json& config) {
    if (!config.contains("richonline_game_bank_policy")) return {};
    const auto& value=config.at("richonline_game_bank_policy");
    if (!value.is_object() || value.size()!=3 || !value.contains("provenance") ||
        !value.contains("admission_padding") || !value.contains("transaction_padding"))
        throw CodecError("richonline_game_bank_policy_fields_invalid");
    if (!value.at("provenance").is_string()) throw CodecError("richonline_game_bank_policy_provenance_required");
    const auto source=value.at("provenance").get<std::string>();
    if (source.size()<8 || source.size()>4096 || source.find('\0')!=source.npos)
        throw CodecError("richonline_game_bank_policy_provenance_required");
    return RichonlineGameBankWirePolicy{
        static_cast<std::uint8_t>(number(value.at("admission_padding"),0,255)),
        numbers<std::uint8_t,2>(value.at("transaction_padding"),0,255)};
}
void fields(const Json& value,std::initializer_list<std::string_view> expected,const char* error) {
    if (!value.is_object() || value.size()!=expected.size()) throw CodecError(error);
    for (const auto name:expected) if (!value.contains(name)) throw CodecError(error);
}
std::string source(const Json& value,const char* error) {
    if (!value.is_string()) throw CodecError(error);
    const auto result=value.get<std::string>();
    if (result.size()<8 || result.size()>400 || result.find('\0')!=result.npos) throw CodecError(error);
    return result;
}
bool boolean(const Json& value) {
    if (!value.is_boolean()) throw CodecError("richonline_runtime_policy_boolean_invalid");
    return value.get<bool>();
}
GameSettlementReward reward(const Json& value) {
    fields(value,{"experience","gold_return","bonus_gold"},"richonline_terminal_reward_fields_invalid");
    return {static_cast<std::uint32_t>(number(value.at("experience"),0,32767)),
        static_cast<std::uint32_t>(number(value.at("gold_return"),0,2147483647)),
        static_cast<std::uint32_t>(number(value.at("bonus_gold"),0,2147483647))};
}
struct TerminalPolicy {
    RichonlineTerminalRules terminal;
    RichonlineBossSettlementRules settlement;
    RichonlineResultDisplayPolicy display;
    RichonlineMapLoadPolicy loading;
    std::string byte18_evidence;
};
std::optional<TerminalPolicy> terminal_policy(const Json& config) {
    if (!config.contains("richonline_terminal_policy")) return {};
    const auto& value=config.at("richonline_terminal_policy");
    fields(value,{"provenance","client_sha256","simultaneous_defeat","win_rank","loss_rank","draw_rank",
        "show_text_270","result_display_ms","map_load_timeout_ms","return_winning_pledge","first_win_bonus","repeat_win_bonus","loss","draw"},
        "richonline_terminal_policy_fields_invalid");
    const auto provenance=source(value.at("provenance"),"richonline_terminal_policy_provenance_required");
    if (!value.at("client_sha256").is_string() || !value.at("simultaneous_defeat").is_string())
        throw CodecError("richonline_terminal_policy_scope_invalid");
    const auto byte18=richonline_boss_result_byte18_compatibility(value.at("client_sha256").get<std::string>(),3);
    const auto simultaneous=value.at("simultaneous_defeat").get<std::string>();
    if (simultaneous!="human_loss" && simultaneous!="draw") throw CodecError("richonline_terminal_policy_scope_invalid");
    const auto win_rank=static_cast<std::int8_t>(number(value.at("win_rank"),1,2));
    const auto loss_rank=static_cast<std::int8_t>(number(value.at("loss_rank"),1,2));
    const auto draw_rank=static_cast<std::int8_t>(number(value.at("draw_rank"),1,2));
    if (win_rank!=1 || loss_rank!=2) throw CodecError("richonline_terminal_policy_rank_invalid");
    const RichonlineResultDisplayPolicy display{std::chrono::milliseconds{number(value.at("result_display_ms"),2700,600000)},
        [] { return std::chrono::steady_clock::now(); }};
    return TerminalPolicy{{provenance,simultaneous=="draw" ? RichonlineSimultaneousDefeat::draw : RichonlineSimultaneousDefeat::human_loss,
        win_rank,loss_rank,draw_rank,byte18.value,boolean(value.at("show_text_270"))},
        {provenance,boolean(value.at("return_winning_pledge")),
            static_cast<std::uint32_t>(number(value.at("first_win_bonus"),0,2147483647)),
            static_cast<std::uint32_t>(number(value.at("repeat_win_bonus"),0,2147483647)),reward(value.at("loss")),reward(value.at("draw"))},
        display,{std::chrono::milliseconds{number(value.at("map_load_timeout_ms"),1000,600000)},
            [] { return std::chrono::steady_clock::now(); }},byte18.evidence};
}
std::optional<RichonlineCombatWorldPolicy> combat_policy(const Json& config) {
    if (!config.contains("richonline_combat_policy")) return {};
    const auto& value=config.at("richonline_combat_policy");
    const bool viewport=value.value("range_name",std::string{})=="server_boss_centered_viewport";
    if(viewport)
        fields(value,{"provenance","range_name","viewport_width","viewport_height","projectile_candidates",
            "mine_landing_policy","neutral_human_equipment"},"richonline_combat_policy_fields_invalid");
    else
        fields(value,{"provenance","range_name","manhattan_radius","projectile_candidates","mine_landing_policy",
            "neutral_human_equipment"},"richonline_combat_policy_fields_invalid");
    (void)source(value.at("provenance"),"richonline_combat_policy_provenance_required");
    if ((!viewport && value.at("range_name")!="server_manhattan_tile_radius") ||
        value.at("mine_landing_policy")!="closed-static-road-v1" ||
        (value.at("projectile_candidates")!="road_tiles" && value.at("projectile_candidates")!="all_map_tiles"))
        throw CodecError("richonline_combat_policy_scope_invalid");
    RichonlineCombatWorldPolicy result{{value.at("range_name").get<std::string>(),
        viewport ? std::uint16_t{0} : static_cast<std::uint16_t>(number(value.at("manhattan_radius"),1,64)),
        value.at("projectile_candidates")=="road_tiles" ? RichonlineProjectileCandidates::road_tiles : RichonlineProjectileCandidates::all_map_tiles},
        {},{},{},{},{}};
    if(viewport) {
        if(result.range.projectile_candidates!=RichonlineProjectileCandidates::road_tiles)
            throw CodecError("richonline_combat_policy_viewport_requires_roads");
        result.range.viewport_width=static_cast<std::uint16_t>(number(value.at("viewport_width"),64,4096));
        result.range.viewport_height=static_cast<std::uint16_t>(number(value.at("viewport_height"),48,4096));
    }
    const auto& neutral=value.at("neutral_human_equipment");
    if (!neutral.is_array() || neutral.size()>32) throw CodecError("richonline_combat_policy_equipment_invalid");
    for (const auto& id:neutral) result.neutral_human_equipment.push_back(static_cast<std::uint16_t>(number(id,1,4095)));
    return result;
}
std::optional<RichonlineCombatRangePolicy> ground_card_policy(const Json& config) {
    if (!config.contains("richonline_ground_card_policy")) return {};
    const auto& value=config.at("richonline_ground_card_policy");
    fields(value,{"provenance","range_name","manhattan_radius"},"richonline_ground_card_policy_fields_invalid");
    (void)source(value.at("provenance"),"richonline_ground_card_policy_provenance_required");
    if (value.at("range_name")!="server_manhattan_tile_radius")
        throw CodecError("richonline_ground_card_policy_scope_invalid");
    return RichonlineCombatRangePolicy{"server_manhattan_tile_radius",
        static_cast<std::uint16_t>(number(value.at("manhattan_radius"),1,64)),
        RichonlineProjectileCandidates::road_tiles};
}
struct NpcWirePolicy {
    std::uint8_t god7,god8,chest7,chest8;
};
std::optional<NpcWirePolicy> npc_wire_policy(const Json& config) {
    if (!config.contains("richonline_npc_policy")) return {};
    const auto& value=config.at("richonline_npc_policy");
    constexpr std::array names{"provenance","god_bytes","chest_bytes"};
    if (!value.is_object() || value.size()!=names.size()) throw CodecError("richonline_npc_policy_fields_invalid");
    for (const auto name:names) if (!value.contains(name)) throw CodecError("richonline_npc_policy_fields_invalid");
    if (!value.at("provenance").is_string()) throw CodecError("richonline_npc_policy_provenance_required");
    const auto source=value.at("provenance").get<std::string>();
    if (source.size()<8 || source.size()>4096 || source.find('\0')!=source.npos)
        throw CodecError("richonline_npc_policy_provenance_required");
    const auto gods=numbers<std::uint8_t,2>(value.at("god_bytes"),0,255);
    const auto chests=numbers<std::uint8_t,2>(value.at("chest_bytes"),0,255);
    return NpcWirePolicy{gods[0],gods[1],chests[0],chests[1]};
}
std::size_t uniform_choice(std::size_t upper_bound) {
    if (upper_bound == 0 || upper_bound > std::numeric_limits<std::uint32_t>::max())
        throw CodecError("richonline_boss_random_bound_invalid");
    const auto bound = static_cast<std::uint32_t>(upper_bound);
    const auto threshold = (std::uint32_t{0}-bound)%bound;
    std::uint32_t random;
    do {
        if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&random),sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            throw CodecError("richonline_boss_random_failed");
    } while (random < threshold);
    return random%bound;
}
std::array<std::int8_t,4> uniform_lost_cards(RichonlineChanceInventory inventory,std::uint8_t limit) {
    return select_richonline_badluck_half(inventory,limit,uniform_choice);
}
std::string payment_identity() {
    std::array<std::uint8_t,16> bytes;
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr,bytes.data(),static_cast<ULONG>(bytes.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        throw CodecError("richonline_payment_identity_random_failed");
    constexpr char hex[]="0123456789abcdef";
    std::string result="new-match-";
    for (const auto byte:bytes) { result.push_back(hex[byte>>4]); result.push_back(hex[byte&15]); }
    return result;
}
}
std::optional<RichonlineRuntimeGame> load_richonline_boss_runtime(
    Storage& storage,const std::filesystem::path& bootstrap,ControlLog log) {
    if (!std::filesystem::exists(bootstrap)) return {};
    std::ifstream stream(bootstrap,std::ios::binary);
    if (!stream) throw CodecError("bootstrap_file_open_failed");
    try {
        const auto config = Json::parse(stream);
        if (!config.is_object()) throw CodecError("richonline_boss_runtime_config_invalid");
        const bool has_host = config.contains("richonline_boss_game"), has_turns = config.contains("richonline_boss_turn_policy");
        if (!has_host && !has_turns && !config.contains("richonline_boss_card_policy") &&
            !config.contains("richonline_game_bank_policy") && !config.contains("richonline_npc_policy") &&
            !config.contains("richonline_terminal_policy") && !config.contains("richonline_combat_policy") &&
            !config.contains("richonline_ground_card_policy")) return {};
        if (storage.client_profile() != ClientProfile::richonline) throw CodecError("richonline_boss_runtime_client_profile_invalid");
        if (!has_host || !has_turns) throw CodecError("richonline_boss_runtime_config_incomplete");
        const auto selected = policy(config.at("richonline_boss_turn_policy"));
        const auto selected_cards = card_policy(config);
        const auto selected_bank = bank_policy(config);
        const auto selected_npcs = npc_wire_policy(config);
        const auto selected_terminal=terminal_policy(config);
        const auto selected_combat=combat_policy(config);
        const auto configured_ground=ground_card_policy(config);
        const auto selected_ground=configured_ground ? configured_ground :
            selected_combat ? std::optional{selected_combat->range} : std::nullopt;
        if (configured_ground && !selected_cards) throw CodecError("richonline_ground_card_cards_required");
        if (selected_combat && (!selected_cards || !selected_terminal))
            throw CodecError("richonline_combat_cards_and_terminal_required");
        if (selected_npcs && !selected_cards) throw CodecError("richonline_npc_cards_required");
        if (selected_cards && !selected_ground) throw CodecError("richonline_ground_card_policy_required");
        const auto root = config.at("richonline_boss_game").at("client_root").get<std::string>();
        if (root.empty() || root.find('\0') != root.npos) throw CodecError("richonline_boss_host_resource_path_invalid");
        std::filesystem::path resources(std::u8string(root.begin(),root.end()));
        if (resources.is_relative()) resources = std::filesystem::absolute(bootstrap).parent_path()/resources;
        resources = resources.lexically_normal();
        const auto chance = selected_cards ? std::make_shared<const RichonlineChanceResources>(RichonlineChanceResources::load(resources)) : nullptr;
        if (selected_cards) static_cast<void>(RichonlineBossCards(chance,1,*selected_cards));
        auto runtime = load_richonline_boss_host(storage,bootstrap,log,[&storage,selected,selected_cards,selected_bank,selected_npcs,
            selected_terminal,selected_combat,selected_ground,chance,resources,log](const RichonlineBossStartup& startup) {
            const auto& extension=startup.room.description.extension;
            if (extension.size()!=88) throw CodecError("richonline_boss_E88_invalid");
            const auto end=std::find(extension.begin(),extension.begin()+32,std::uint8_t{0});
            const auto& package=find_richonline_map_package(std::string(extension.begin(),end),
                read_le(View(extension).subspan(68,4)));
            RichonlineBossSessionPolicy session_policy{selected.opaque_turn7,selected.inactive_ui_dice,
                {selected.opaque20_23,0,selected.optional_tail},uniform_choice,selected_cards,selected_bank};
            session_policy.script_database=[&storage](const LuaValue& request) {return storage.script_batch(request);};
            RichonlineStartupPlan raw_plan{startup.init,startup.snapshot,startup.envelope,{},{},{}};
            auto raw_authority=attach_richonline_raw_authority(raw_plan);
            const bool closed_raw=package.raw_status_policy==RichonlineMapRawStatusPolicy::closed_boss_initial_status;
            if(closed_raw) session_policy.raw_authority=raw_authority;
            if (closed_raw) session_policy.hibernate_raw_actor=[raw_authority](std::uint8_t actor) {
                return raw_authority->actor(actor);
            };
            session_policy.portal_scripted_state=[raw_authority] {
                const auto value=raw_authority->game().scripted_event83830;
                if (!value) throw CodecError("richonline_raw_game_unknown");
                return static_cast<std::int32_t>(*value);
            };
            // The host has already validated the admitted owner and allows only
            // empty equipment or the non-modifying RP certificate at startup.
            const auto account=storage.game_account_for_role(startup.room.owner);
            const auto match=payment_identity();
            session_policy.payment=RichonlineBossSessionPolicy::AccountPayment{account.gold,match,
                [&storage,username=account.username,role=startup.room.owner](const GameGoldCharge& charge) {
                    return storage.consume_game_gold(username,role,charge);
                },{false,false}};
            if (selected_terminal) {
                const auto stage=package.load_stage(resources,read_le(View(extension).subspan(68,4)));
                const auto settlement=richonline_boss_settlement_policy(stage,load_richonline_level_thresholds(resources),
                    selected_terminal->settlement);
                session_policy.terminal=std::make_shared<RichonlineTerminalCoordinator>(storage,
                    RichonlineTerminalContext{account.username,startup.room.owner,startup.init.game_server_id,startup.room.key,
                        {match+":settlement",match,stage.map_name+":category="+std::to_string(read_le(View(extension).subspan(68,4))),
                            GameOutcome::loss,stage.pawn_gold,{},settlement},
                        {3,0,{1},{}},selected_terminal->terminal,selected_terminal->byte18_evidence});
                session_policy.result_display=selected_terminal->display;
                session_policy.map_loading=selected_terminal->loading;
            }
            if (selected_ground) {
                const auto stage=package.load_stage(resources,read_le(View(extension).subspan(68,4)));
                const auto topology=load_richonline_road_topology(resources/"Map"/stage.map_name);
                session_policy.ground_card_visible=make_richonline_ground_card_authority(
                    topology,startup.init.participants.size(),selected_ground);
            }
            if (selected_combat) {
                session_policy.combat=*selected_combat;
                // Constructor state and card-driven jail clocks share this raw
                // authority. Unknown transitions still fail before mutation.
                if (closed_raw) {
                    const auto stage=package.load_stage(resources,read_le(View(extension).subspan(68,4)));
                    const auto topology=load_richonline_road_topology(resources/"Map"/stage.map_name);
                    session_policy.timed_bombs=std::make_shared<const RichonlineTimedBombTurnPolicy>(
                    RichonlineTimedBombTurnPolicy{
                        std::make_shared<const RichonlineTimedBombRules>(RichonlineTimedBombRules::load(resources)),
                        static_cast<std::uint8_t>(uniform_choice(256)),
                        [raw_authority,topology](std::uint8_t actor,std::int16_t position) {
                            if (!topology.cell(position).walkable)
                                throw CodecError("richonline_raw_step_not_road");
                            return raw_authority->timed_bomb_step_context(actor,position);
                        }});
                }
                // The session binds mine legality to its actual shared
                // landing preflight after assembling the room capabilities.
            }
            if (selected_npcs) {
                if (!package.closed_npcs) throw CodecError("richonline_map_npc_policy_unimplemented");
                const auto& map=*package.closed_npcs;
                if (map.max_transfer<0) throw CodecError("richonline_map_npc_transfer_invalid");
                const RichonlineNpcSpawnPolicy spawn{map.initial_gods,map.initial_chests,map.minimum_objects,
                    map.maximum_objects,map.refresh_every_rounds,map.god_pool,selected_npcs->god7,selected_npcs->god8,
                    selected_npcs->chest7,selected_npcs->chest8,map.refresh_chests};
                session_policy.npcs=RichonlineNpcSessionPolicy{spawn,
                    static_cast<std::uint32_t>(uniform_choice(std::numeric_limits<std::uint32_t>::max())),
                    map.fortune_cards,{richonline_unassigned_player_team,richonline_synthetic_boss_team},
                    {load_richonline_npc_affix(resources,0),load_richonline_npc_affix(resources,1)},
                    "native-uniform-solvent-transfer-v1",
                     [maximum=map.max_transfer,terminal_enabled=selected_terminal.has_value()](std::uint8_t actor,std::int8_t npc,const auto& funds) {
                        if (actor>=2 || (npc!=0 && npc!=1)) throw CodecError("richonline_npc_money_context_invalid");
                        const auto payer=npc==0 ? static_cast<std::uint8_t>(1U-actor) : actor;
                        const auto receiver=static_cast<std::uint8_t>(1U-payer);
                        const auto& balance=funds[payer].funds;
                        if (!balance.deposit) throw CodecError("richonline_npc_deposit_unknown");
                        const auto available=static_cast<std::uint64_t>(balance.cash)+*balance.deposit;
                        const auto& recipient=funds[receiver].funds;
                        if (!recipient.deposit) throw CodecError("richonline_npc_deposit_unknown");
                        const auto recipient_total=static_cast<std::uint64_t>(recipient.cash)+*recipient.deposit;
                        if (recipient_total>static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
                            throw CodecError("richonline_npc_money_total_out_of_range");
                        const auto room=static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())-recipient_total;
                         // Without a terminal capability, the named partial-game
                         // policy keeps a solvent payer alive. With settlement
                         // enabled, a real NPC transfer can finish the match.
                         const auto payable=terminal_enabled ? available : (available ? available-1 : 0);
                         const auto bound=std::min({static_cast<std::uint64_t>(maximum),payable,room});
                        return static_cast<std::int16_t>(uniform_choice(static_cast<std::size_t>(bound+1)));
                    }};
                if (map.badluck) {
                    if (map.badluck->selection!=RichonlineMapBadluckSelection::uniform_inventory_units_without_replacement)
                        throw CodecError("richonline_map_badluck_selection_invalid");
                    session_policy.npcs->badluck=RichonlineNpcBadluckPolicy{load_richonline_npc_affix(resources,2),
                        "native-half-floor-uniform-inventory-units-without-replacement-v2",
                        [limit=map.badluck->lost_card_limit](const RichonlineChanceInventory& inventory) {
                            return uniform_lost_cards(inventory,limit);
                        }};
                }
                if (map.initial_chests || map.refresh_chests)
                    session_policy.npcs->ticket_chest=RichonlineTicketChestRules::load(resources);
            }
            auto plan=make_richonline_boss_session(resources,startup,package,session_policy,chance,log);
            auto raw_sent=std::move(raw_plan.sent);
            plan.sent=[raw_sent=std::move(raw_sent),sent=std::move(plan.sent)](View plain) {
                raw_sent(plain);
                if (sent) sent(plain);
            };
            plan.disconnected=[raw_close=std::move(raw_plan.disconnected),close=std::move(plan.disconnected)] {
                raw_close();
                close();
            };
            // All map/codec/capability checks run first. Only then hold the real
            // entry pledge; failed admission cleanup returns this same receipt.
            if (session_policy.terminal) {
                try { (void)session_policy.terminal->prepare_start(); }
                catch (const StorageError& error) {
                    // This is a normal ready refusal, handled by the existing
                    // lobby cancellation path. Real persistence faults stay errors.
                    if (std::string_view(error.what())=="game_pledge_insufficient_funds")
                        throw CodecError(error.what());
                    throw;
                }
            }
            return plan;
        });
        if (log) log("richonline_boss_runtime_configured",{{"scope",scope},{"provenance",selected.provenance},
            {"paid_rolls_supported",true},{"controlled_dice_card_supported",selected_cards.has_value()},
            {"game_bank_supported",selected_bank.has_value()},
            {"closed_npc_flow_supported",selected_npcs.has_value()},
            {"terminal_economics_supported",selected_terminal.has_value()},
            {"combat_session_supported",selected_combat.has_value()},
            {"ground_card_range_configured",selected_ground.has_value()},
            {"timed_bomb_session_supported",selected_combat.has_value()},
            {"timed_bomb_raw_policy","closed_initial_status_policy"},
            {"timed_bomb_unconsumed_byte_policy","system-random-unconsumed"},
            {"item_rewards_delivered",false},
            {"runtime_client_verified",false},{"game_ready",false}});
        return runtime;
    } catch (const Json::exception&) { throw CodecError("richonline_boss_runtime_json_invalid"); }
}
}
