#include "richonline_boss_startup.hpp"
#include "richonline_boss_stage.hpp"
#include "richonline_map_package.hpp"
#include "original_map.hpp"
#include "original_options.hpp"
#include "richonline_combat_resources.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <limits>
#include <map>
#include <string_view>

namespace richnet {
namespace {
using Record = std::map<std::string, std::string, std::less<>>;
std::uint32_t word(View bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4) throw CodecError("richonline_boss_resource_truncated");
    return read_le(bytes.subspan(offset,4));
}
std::string_view trim(std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r");
    return first == value.npos ? std::string_view{} : value.substr(first,value.find_last_not_of(" \t\r")-first+1);
}
std::vector<Record> records(const std::filesystem::path& file, std::string_view section) {
    // Container-only reuse: new 81B4C0/81B7F0 and 7DF010 use the same byte-key/LZO layout.
    const auto bytes = load_original_kpd(file);
    std::string_view text(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    std::vector<Record> result;
    bool selected = false;
    while (!text.empty()) {
        const auto end = text.find('\n');
        const auto line = trim(text.substr(0,end));
        text = end == text.npos ? std::string_view{} : text.substr(end+1);
        if (line.empty() || line.starts_with("//") || line.front() == ';') continue;
        if (line.front() == '[') {
            selected = line == section;
            if (selected) result.emplace_back();
        } else if (selected) {
            const auto separator = line.find('=');
            if (separator != line.npos && !result.back().emplace(trim(line.substr(0,separator)),trim(line.substr(separator+1))).second)
                throw CodecError("richonline_boss_resource_duplicate_key");
        }
    }
    return result;
}
std::int32_t integer(std::string_view text) {
    std::int32_t result = 0;
    const auto parsed = std::from_chars(text.data(),text.data()+text.size(),result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size()) throw CodecError("richonline_boss_resource_number_invalid");
    return result;
}
std::int32_t value(const Record& record, std::string_view key) {
    const auto found = record.find(key);
    if (found == record.end()) throw CodecError("richonline_boss_resource_key_missing");
    return integer(found->second);
}
std::uint32_t positive_or_zero(std::int64_t number) {
    if (number < 0 || number > std::numeric_limits<std::int32_t>::max()) throw CodecError("richonline_boss_cash_out_of_range");
    return static_cast<std::uint32_t>(number);
}
std::int32_t effect(std::string_view text, std::int32_t cash) {
    const auto condition = text.find('(');
    const auto amount = integer(trim(text.substr(0,condition)));
    if (condition == text.npos) return amount;
    const auto tail = text.substr(condition);
    if (tail.size() < 4 || tail.back() != ')' || (tail[1] != '<' && tail[1] != '>'))
        throw CodecError("richonline_boss_effect_condition_invalid");
    const auto threshold = integer(tail.substr(2,tail.size()-3));
    return ((tail[1] == '<' && cash < threshold) || (tail[1] == '>' && cash > threshold)) ? amount : 0;
}
std::uint32_t equipment_cash(std::uint32_t initial, std::span<const std::uint32_t> equipment, const std::vector<Record>& props) {
    const auto base = static_cast<std::int32_t>(initial);
    std::int64_t flat = 0, percent = 0;
    for (const auto item : equipment) {
        const auto id = item & 0xfffU;
        if (id == 0) continue;
        for (const auto& prop : props) {
            if (value(prop,"indx") != static_cast<std::int32_t>(id) || !prop.contains("att_desc")) continue;
            if (prop.contains("moneyV")) flat += effect(prop.at("moneyV"),base);
            if (prop.contains("moneyR")) percent += effect(prop.at("moneyR"),base);
        }
    }
    if (percent < std::numeric_limits<std::int32_t>::min() || percent > std::numeric_limits<std::int32_t>::max())
        throw CodecError("richonline_boss_cash_out_of_range");
    // 7F44B4..7F44E0: signed low32 product, signed division toward zero.
    const auto product = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(base) * static_cast<std::uint32_t>(percent));
    return positive_or_zero(static_cast<std::int64_t>(base)+product/100+flat);
}
}
RichonlineBossStartup build_richonline_boss_startup(const std::filesystem::path& client_root,
    const RichonlineRoomSnapshot& room, const RichonlineBossStartupInput& input) {
    const auto& extension = room.description.extension;
    const View e(extension), record(room.description.record);
    if (e.size() != 88 || word(record,120) != 88 || (word(record,32)&0x40U) == 0)
        throw CodecError("richonline_boss_E88_invalid");
    if (input.human_identity < 0 || room.participants.size() != 1 || room.owner != static_cast<std::uint32_t>(input.human_identity) ||
        room.participants.front().actor != room.owner || !room.participants.front().ready)
        throw CodecError("richonline_boss_membership_invalid");
    RichonlineCombatModifierResources::load(client_root).validate_supported_equipment(input.profile_slots);
    if (std::any_of(input.building_skill_caps.begin(),input.building_skill_caps.end(),[](auto v) { return v < 0 || v > 7; }))
        throw CodecError("richonline_boss_skill_caps_invalid");
    const auto name_end = std::find(e.begin(),e.begin()+32,std::uint8_t{0});
    const std::string map_name(e.begin(),name_end);
    if (word(e,48) != 3) throw CodecError("richonline_boss_mode_unsupported");
    if (word(e,52) != 1) throw CodecError("richonline_boss_capacity_unsupported");
    if (word(record,36) != word(e,48) || word(record,40) != word(e,52))
        throw CodecError("richonline_boss_public_room_mismatch");
    const auto stage = load_richonline_boss_stage(client_root,map_name,word(e,68));
    if (!std::equal(stage.signature.begin(),stage.signature.end(),e.begin()+32)) throw CodecError("richonline_boss_map_signature_mismatch");
    if (stage.player_count_choices != std::vector<std::uint32_t>{1,2,3,4}) throw CodecError("richonline_boss_stage_unsupported");
    if (word(e,56) != stage.wait_seconds || word(e,60) != stage.game_months || word(e,64) != stage.pawn_gold)
        throw CodecError("richonline_boss_room_resource_mismatch");
    const auto map = load_original_emp(client_root / "Map" / stage.map_name);
    const auto& package=find_richonline_map_package(stage.map_name,stage.category);
    std::array<RichonlineMapSpawnChoice,2> positions{};
    try {
        positions=choose_richonline_map_spawns(richonline_road_topology(map),package.resource_rules.spawn_policy,input.spawn_random);
    } catch(const CodecError& error) {
        if(std::string_view(error.what())=="richonline_map_rules_spawn_graph_disconnected")
            throw CodecError("richonline_boss_spawn_graph_disconnected");
        throw;
    }
    const auto& w = input.wire;
    RichonlineBoardInit init{w.game_server_id,w.opaque_f64,w.year,w.month,w.day,w.weekday,0,w.opaque_header_byte,
        {{input.human_identity,positions[0].position,positions[0].direction,input.building_skill_caps,w.opaque_trailing[0]},
         {-1,positions[1].position,positions[1].direction,w.synthetic_unconsumed_skill_bytes,w.opaque_trailing[1]}}};
    const auto props=records(client_root / "Data" / "Prop.kpd","[PROP]");
    const auto initial_boss_cash = equipment_cash(stage.boss.base_cash,stage.boss.equipment,props);
    // NEW7F3C70 对人类和 BOSS 都应用同一套初始现金加成；快照覆盖客户端本地值。
    const auto initial_human_cash = equipment_cash(stage.human.cash,input.profile_slots,props);
    // New 7DF010 tail fields26..29; 7F3840 explicitly initializes BOSS deposit/tickets to0.
    RichonlineBoardSnapshot snapshot{w.game_server_id,w.calendar_counter,stage.monetary_scale,
        {{initial_human_cash,stage.human.deposit,stage.human.tickets},
         {initial_boss_cash,0,0}}};
    static_cast<void>(encode_richonline_board_init(init));
    static_cast<void>(encode_richonline_board_snapshot(snapshot));
    return {room,std::move(init),std::move(snapshot),w.envelope,input.profile_slots};
}
}
