#include "richonline_chance.hpp"
#include "original_options.hpp"
#include "original_map.hpp"
#include <algorithm>
#include <charconv>
#include <limits>
#include <utility>

namespace richnet {
namespace {
constexpr auto resource_limit = 4U*1024U*1024U;
using Fields = std::map<std::string,std::string,std::less<>>;
std::string_view trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r");
    return begin == std::string_view::npos ? std::string_view{} :
        text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);
}
std::vector<std::string_view> split(std::string_view text, char separator) {
    std::vector<std::string_view> result;
    for (;;) {
        const auto end = text.find(separator);
        result.push_back(text.substr(0,end));
        if (end == std::string_view::npos) return result;
        text.remove_prefix(end+1);
    }
}
void text_boundary(std::string_view text) {
    if (text.size() > resource_limit || text.find('\0') != std::string_view::npos)
        throw CodecError("richonline_chance_text_invalid");
}
std::int32_t number(std::string_view text, std::string_view error) {
    if (text.empty()) throw CodecError(std::string(error));
    std::int32_t result = 0;
    const auto parsed = std::from_chars(text.data(),text.data()+text.size(),result);
    if (text.find_first_not_of("0123456789") != std::string_view::npos ||
        parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size())
        throw CodecError(std::string(error));
    return result;
}
std::int16_t card_id(std::string_view text, std::string_view error) {
    const auto result = number(trim(text),error);
    if (result < 1 || result > std::numeric_limits<std::int16_t>::max())
        throw CodecError(std::string(error));
    return static_cast<std::int16_t>(result);
}
std::vector<Fields> records(std::string_view text, std::string_view section) {
    text_boundary(text);
    std::vector<Fields> result;
    for (auto line : split(text,'\n')) {
        line = trim(line);
        if (line.empty() || line.starts_with("//") || line.front() == ';' || line.front() == '#') continue;
        if (line.front() == '[') {
            if (line != section || (!result.empty() && result.back().empty()) || result.size() >= 32768)
                throw CodecError("richonline_chance_section_invalid");
            result.emplace_back(); continue;
        }
        const auto separator = line.find('=');
        if (result.empty() || separator == std::string_view::npos || trim(line.substr(0,separator)).empty())
            throw CodecError("richonline_chance_field_invalid");
        if (!result.back().emplace(trim(line.substr(0,separator)),trim(line.substr(separator+1))).second)
            throw CodecError("richonline_chance_field_duplicate");
    }
    if (!result.empty() && result.back().empty()) throw CodecError("richonline_chance_section_invalid");
    return result;
}
std::string_view required(const Fields& fields, std::string_view key) {
    const auto found = fields.find(key);
    if (found == fields.end()) throw CodecError("richonline_chance_field_missing");
    return found->second;
}
std::set<std::int16_t> map_membership(const OriginalEmp& emp) {
    const View bytes(emp.payload);
    auto cursor = emp.tail_offset;
    const auto skip = [&](std::size_t count, std::size_t stride) {
        if (cursor > bytes.size() || count > (bytes.size()-cursor)/stride)
            throw CodecError("richonline_chance_map_truncated");
        cursor += count*stride;
    };
    const auto word = [&] {
        skip(1,4);
        return read_le(bytes.subspan(cursor-4,4));
    };
    // New 7DF010: 120 fixed tail bytes, count/DWORD array, then count/eight-byte card rows.
    skip(120,1);
    const auto unknown_count = word();
    skip(unknown_count,4);
    const auto card_count = word();
    if (card_count > 32768) throw CodecError("richonline_chance_map_cards_invalid");
    std::set<std::int16_t> result;
    for (std::uint32_t i = 0; i < card_count; ++i) {
        const auto id = word();
        skip(1,4);
        if (id == 0 || id > 32767 || !result.insert(static_cast<std::int16_t>(id)).second)
            throw CodecError("richonline_chance_map_cards_invalid");
    }
    return result;
}
}

RichonlineChanceResources RichonlineChanceResources::parse(std::string_view news,
    std::string_view props, std::string_view combinations, RichonlineChanceMapMembership membership) {
    text_boundary(news);
    RichonlineChanceResources result;
    result.membership_ = std::move(membership);
    for (auto line : split(news,'\n')) {
        line = trim(line);
        if (line.empty()) continue;
        const auto columns = split(line,'\t');
        if (columns.size() != 10 || columns[0].empty()) throw CodecError("richonline_chance_news_invalid");
        const auto category = number(columns[1],"richonline_chance_news_invalid");
        if (category > 16) throw CodecError("richonline_chance_news_invalid");
        Event event{category,{}};
        if (category == 5) {
            for (const auto candidate : split(columns[7],','))
                if (!event.cards.insert(card_id(candidate,"richonline_chance_news_invalid")).second)
                    throw CodecError("richonline_chance_news_invalid");
        }
        auto& map_events = result.events_[std::string(columns[0])];
        if (map_events.size() >= 32768) throw CodecError("richonline_chance_news_invalid");
        map_events.push_back(std::move(event));
    }
    if (result.events_.empty()) throw CodecError("richonline_chance_news_invalid");
    std::set<std::int32_t> prop_ids;
    for (const auto& entry : records(props,"[PROP]")) {
        const auto id = number(required(entry,"indx"),"richonline_chance_prop_invalid");
        if (!prop_ids.insert(id).second) throw CodecError("richonline_chance_prop_duplicate");
        if(required(entry,"type")=="CARD" && id>=0 && id<=std::numeric_limits<std::int16_t>::max())
            result.card_types_.insert(static_cast<std::int16_t>(id));
        if (required(entry,"type") == "CARD" && required(entry,"enable") == "true" &&
            id > 0 && id <= std::numeric_limits<std::int16_t>::max())
            result.cards_.insert(static_cast<std::int16_t>(id));
    }
    if (prop_ids.empty()) throw CodecError("richonline_chance_prop_invalid");
    for (const auto& entry : records(combinations,"[ITEM]")) {
        const auto enabled = required(entry,"enable");
        if (enabled == "false") continue;
        if (enabled != "true") throw CodecError("richonline_chance_combination_invalid");
        std::map<std::int16_t,std::int32_t> sources;
        for (const auto& [key,value] : entry) {
            if (!key.starts_with("src")) continue;
            const auto index = number(std::string_view(key).substr(3),"richonline_chance_combination_invalid");
            const auto pair = split(value,',');
            if (index > 7 || pair.size() != 2) throw CodecError("richonline_chance_combination_invalid");
            const auto card = card_id(pair[0],"richonline_chance_combination_invalid");
            const auto count = number(trim(pair[1]),"richonline_chance_combination_invalid");
            if (count < 1 || !sources.emplace(card,count).second)
                throw CodecError("richonline_chance_combination_invalid");
        }
        if (sources.empty()) throw CodecError("richonline_chance_combination_invalid");
        const auto destination = card_id(required(entry,"dest"),"richonline_chance_combination_invalid");
        result.combinations_.push_back({destination,std::move(sources)});
    }
    return result;
}

RichonlineChanceResources RichonlineChanceResources::load(const std::filesystem::path& root) {
    const auto news = load_original_kpd(root/"Data"/"BwNews.kpd");
    const auto props = load_original_kpd(root/"Data"/"Prop.kpd");
    const auto combinations = load_original_kpd(root/"Data"/"CombCard.kpd");
    const auto text = [](const Bytes& bytes) {
        return std::string_view(reinterpret_cast<const char*>(bytes.data()),bytes.size());
    };
    auto result = parse(text(news),text(props),text(combinations));
    for (const auto& [map,events] : result.events_) {
        const std::filesystem::path filename(map);
        if (filename.has_parent_path() || filename.extension() != ".emp")
            throw CodecError("richonline_chance_map_name_invalid");
        result.membership_.emplace(map,map_membership(load_original_emp(root/"Map"/filename)));
    }
    return result;
}

RichonlineChanceSingleCard RichonlineChanceResources::single_card(std::string_view map,
    std::int32_t event, std::int32_t card) const {
    const auto found = events_.find(map);
    if (found == events_.end()) throw CodecError("richonline_chance_map_missing");
    if (event < 0 || static_cast<std::size_t>(event) >= found->second.size())
        throw CodecError("richonline_chance_event_invalid");
    const auto& selected = found->second[static_cast<std::size_t>(event)];
    if (selected.category != 5) throw CodecError("richonline_chance_category_unsupported");
    if (card < 1 || card > std::numeric_limits<std::int16_t>::max() ||
        !cards_.contains(static_cast<std::int16_t>(card))) throw CodecError("richonline_chance_card_invalid");
    if (!selected.cards.contains(static_cast<std::int16_t>(card)))
        throw CodecError("richonline_chance_card_not_candidate");
    return {static_cast<std::int16_t>(event),static_cast<std::int16_t>(card),map};
}
bool RichonlineChanceResources::automatic_card_eligible(std::string_view map,std::int16_t card) const {
    if(!card_types_.contains(card)) return false;
    const auto found=membership_.find(map);
    if(found==membership_.end()) throw CodecError("richonline_chance_map_membership_missing");
    return found->second.contains(card);
}

RichonlineChanceInventory RichonlineChanceResources::insert(const RichonlineChanceSingleCard& award,
    const RichonlineChanceInventory& inventory) const {
    static_cast<void>(single_card(award.map(),award.event_id(),award.card_id()));
    const auto result = add(award.map(),award.card_id(),1,inventory);
    if (std::none_of(inventory.begin(),inventory.end(),[](const auto& slot) { return slot.card_id == -1; }))
        throw CodecError("richonline_chance_inventory_full");
    return result;
}

RichonlineChanceInventory RichonlineChanceResources::add(std::string_view map, std::int16_t card,
    std::int16_t count, const RichonlineChanceInventory& inventory) const {
    if (!cards_.contains(card) || count <= 0) throw CodecError("richonline_chance_card_invalid");
    std::optional<std::size_t> empty;
    for (std::size_t i = 0; i < inventory.size(); ++i) {
        const auto& slot = inventory[i];
        if (slot.card_id == -1) {
            if (slot.count != 0) throw CodecError("richonline_chance_inventory_invalid");
            if (!empty) empty = i;
        } else {
            if (slot.count <= 0 || !cards_.contains(slot.card_id))
                throw CodecError("richonline_chance_inventory_invalid");
        }
    }
    if (!empty) return inventory;
    auto result = inventory;
    result[*empty] = {card,count};
    const auto map_cards = membership_.find(map);
    for (const auto& recipe : combinations_) {
        if (map_cards != membership_.end() && !map_cards->second.contains(recipe.destination)) continue;
        std::array<bool,8> selected{};
        bool complete = true;
        for (const auto& [source,required_count] : recipe.sources) {
            std::int32_t found = 0;
            for (std::size_t i=0; i<result.size() && found<required_count; ++i) {
                if (result[i].card_id == source) { selected[i]=true; ++found; }
            }
            if (found != required_count) { complete=false; break; }
        }
        if (!complete) continue;
        if (map_cards == membership_.end()) throw CodecError("richonline_chance_combination_membership_missing");
        if (!cards_.contains(recipe.destination)) throw CodecError("richonline_chance_combination_destination_invalid");
        std::optional<std::size_t> destination;
        for (std::size_t i=0; i<result.size(); ++i) if (selected[i]) {
            result[i]={}; if (!destination) destination=i;
        }
        result[*destination]={recipe.destination,1};
    }
    return result;
}

RichonlineChanceInventory RichonlineChanceResources::discard(const RichonlineChanceInventory& inventory,
    std::int8_t slot) const {
    if (slot<0 || slot>=8) throw CodecError("richonline_card_discard_slot_invalid");
    auto result=inventory;
    result[static_cast<std::size_t>(slot)]={};
    return result;
}

Bytes encode_richonline_chance_single_card(std::uint16_t game_id,
    const RichonlineChanceSingleCard& award, std::array<std::uint8_t,2> opaque6_7) {
    Bytes result;
    result.reserve(12);
    append_le(result,0x4096,2);
    append_le(result,game_id,2);
    append_le(result,static_cast<std::uint16_t>(award.event_id()),2);
    result.insert(result.end(),opaque6_7.begin(),opaque6_7.end());
    append_le(result,static_cast<std::uint16_t>(award.card_id()),4);
    return result;
}
}
