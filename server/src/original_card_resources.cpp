#include "original_card_resources.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>
#include <limits>
#include <set>

namespace richnet {
namespace {
constexpr std::size_t text_limit = 4U*1024U*1024U;
constexpr std::size_t record_limit = 4096;
constexpr std::size_t field_limit = 256;
std::string_view trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r");
    return begin == std::string_view::npos ? std::string_view{} : text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);
}
std::string lower_ascii(std::string_view text) {
    std::string result;
    for (const char raw_byte : text) {
        const auto byte = static_cast<unsigned char>(raw_byte);
        if (!(byte >= 'A' && byte <= 'Z') && !(byte >= 'a' && byte <= 'z') &&
            !(byte >= '0' && byte <= '9') && byte != '_') throw CodecError("original_card_key_invalid");
        result.push_back(static_cast<char>(byte >= 'A' && byte <= 'Z' ? byte+('a'-'A') : byte));
    }
    return result;
}
std::vector<OriginalSourceFields> records(View decoded, std::string_view section) {
    if (decoded.empty() || decoded.size() > text_limit || std::find(decoded.begin(),decoded.end(),0) != decoded.end())
        throw CodecError("original_card_text_invalid");
    std::string_view remaining(reinterpret_cast<const char*>(decoded.data()),decoded.size());
    std::vector<OriginalSourceFields> result;
    while (!remaining.empty()) {
        const auto newline = remaining.find('\n');
        const auto line = trim(remaining.substr(0,newline));
        remaining = newline == std::string_view::npos ? std::string_view{} : remaining.substr(newline+1);
        if (line.empty() || line.starts_with("//") || line.front() == ';' || line.front() == '#') continue;
        if (line.front() == '[') {
            if (line.back() != ']' || lower_ascii(trim(line.substr(1,line.size()-2))) != section)
                throw CodecError("original_card_section_invalid");
            if ((!result.empty() && result.back().empty()) || result.size() >= record_limit)
                throw CodecError("original_card_records_invalid");
            result.emplace_back(); continue;
        }
        const auto separator = line.find_first_of("=:");
        if (result.empty() || separator == std::string_view::npos) throw CodecError("original_card_field_invalid");
        const auto key = trim(line.substr(0,separator));
        if (key.empty() || key.size() > 128 || result.back().size() >= field_limit) throw CodecError("original_card_field_invalid");
        static_cast<void>(lower_ascii(key));
        if (!result.back().emplace(key,trim(line.substr(separator+1))).second)
            throw CodecError("original_card_field_duplicate");
    }
    if (result.empty() || result.back().empty()) throw CodecError("original_card_records_invalid");
    return result;
}
std::optional<std::string_view> field(const OriginalSourceFields& fields, std::string_view key) {
    const auto found = fields.find(std::string(key));
    if (found != fields.end()) return found->second;
    return std::nullopt;
}
std::string_view required(const OriginalSourceFields& fields, std::string_view key) {
    const auto found = field(fields,key);
    if (!found) throw CodecError("original_card_field_missing");
    return *found;
}
std::int32_t number(std::string_view value, std::int32_t maximum) {
    if (value.empty() || value.find_first_not_of("0123456789") != std::string_view::npos)
        throw CodecError("original_card_integer_invalid");
    std::int32_t result = 0;
    const auto parsed = std::from_chars(value.data(),value.data()+value.size(),result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data()+value.size() || result > maximum)
        throw CodecError("original_card_integer_range");
    return result;
}
std::int16_t card_id(std::string_view value) {
    const auto id = number(value,32767);
    if (id == 0) throw CodecError("original_card_id_invalid");
    return static_cast<std::int16_t>(id);
}
std::int32_t signed_number(std::string_view value) {
    const auto digits = value.starts_with('-') ? value.substr(1) : value;
    if (digits.empty() || digits.find_first_not_of("0123456789") != std::string_view::npos)
        throw CodecError("original_card_integer_invalid");
    std::int32_t result = 0;
    const auto parsed = std::from_chars(value.data(),value.data()+value.size(),result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data()+value.size()) throw CodecError("original_card_integer_range");
    return result;
}
std::optional<bool> boolean(const OriginalSourceFields& fields, std::string_view key, bool first_component) {
    const auto value = field(fields,key);
    if (!value) return std::nullopt;
    return (first_component ? value->substr(0,value->find(',')) : *value) == "true";
}
}

OriginalPropCards parse_original_prop_cards(Bytes decoded) {
    auto entries = records(decoded,"prop");
    std::set<std::int16_t> ids;
    OriginalPropCards result{std::move(decoded),{}};
    for (auto& entry : entries) {
        const auto id = card_id(required(entry,"indx"));
        if (!ids.insert(id).second) throw CodecError("original_card_id_duplicate");
        const auto type = required(entry,"type");
        if (type.empty()) throw CodecError("original_card_type_invalid");
        if (type != "CARD") continue;
        const auto price = field(entry,"priceG"), fold = field(entry,"fold");
        result.cards.push_back({id,boolean(entry,"enable",true),boolean(entry,"saleG",false),
            price ? std::optional<std::int32_t>{signed_number(*price)} : std::nullopt,
            fold ? std::optional<std::int32_t>{signed_number(*fold)} : std::nullopt,
            std::move(entry)});
    }
    return result;
}
OriginalPropCards load_original_prop_cards(const std::filesystem::path& path) {
    return parse_original_prop_cards(load_original_kpd(path,text_limit));
}
OriginalCardCombinations parse_original_card_combinations(Bytes decoded) {
    auto entries = records(decoded,"item");
    OriginalCardCombinations result{std::move(decoded),{}};
    for (auto& entry : entries) {
        OriginalCombination item{{},card_id(required(entry,"dest")),required(entry,"enable") == "true",{}};
        bool has_source = false;
        for (std::size_t index = 0; index < item.sources.size(); ++index) {
            const auto source = field(entry,"src"+std::to_string(index));
            if (!source) break;
            const auto value = *source;
            const auto comma = value.find(',');
            if (comma == std::string_view::npos || value.find(',',comma+1) != std::string_view::npos)
                throw CodecError("original_combination_source_invalid");
            const auto card = card_id(trim(std::string_view(value).substr(0,comma)));
            const auto count = number(trim(std::string_view(value).substr(comma+1)),std::numeric_limits<std::int32_t>::max());
            if (count == 0) throw CodecError("original_combination_source_invalid");
            item.sources[index] = OriginalCombinationSource{card,count};
            has_source = true;
        }
        if (!has_source) throw CodecError("original_combination_source_missing");
        item.source_fields = std::move(entry);
        result.items.push_back(std::move(item));
    }
    return result;
}
OriginalCardCombinations load_original_card_combinations(const std::filesystem::path& path) {
    return parse_original_card_combinations(load_original_kpd(path,text_limit));
}
}
