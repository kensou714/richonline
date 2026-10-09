#include "original_game_values.hpp"
#include "original_options.hpp"
#include <algorithm>
#include <charconv>

namespace richnet {
namespace {
constexpr std::size_t text_limit = 4U*1024U*1024U;
constexpr std::size_t entry_limit = 4096;
std::string_view trim(std::string_view text) {
    const auto begin = text.find_first_not_of(" \t\r");
    return begin == std::string_view::npos ? std::string_view{} : text.substr(begin,text.find_last_not_of(" \t\r")-begin+1);
}
std::int32_t integer(std::string_view text) {
    const auto digits = text.starts_with('-') ? text.substr(1) : text;
    if (digits.empty() || digits.find_first_not_of("0123456789") != std::string_view::npos)
        throw CodecError("original_game_value_integer_invalid");
    std::int32_t value = 0;
    const auto parsed = std::from_chars(text.data(),text.data()+text.size(),value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size()) throw CodecError("original_game_value_integer_range");
    return value;
}
void append(OriginalGameValues& values, OriginalSourceFields fields) {
    const auto index = fields.find("indx"), value = fields.find("value");
    if (index == fields.end() || value == fields.end()) throw CodecError("original_game_value_field_missing");
    const auto id = integer(index->second), amount = integer(value->second);
    if (id < 0) throw CodecError("original_game_value_index_invalid");
    if (!values.entries.emplace(id,OriginalGameValue{amount,std::move(fields)}).second)
        throw CodecError("original_game_value_index_duplicate");
}
}
OriginalGameValues parse_original_game_values(Bytes decoded) {
    if (decoded.empty() || decoded.size() > text_limit || std::find(decoded.begin(),decoded.end(),0) != decoded.end())
        throw CodecError("original_game_values_text_invalid");
    std::string_view remaining(reinterpret_cast<const char*>(decoded.data()),decoded.size());
    OriginalGameValues values;
    OriginalSourceFields fields;
    bool in_item = false;
    while (!remaining.empty()) {
        const auto newline = remaining.find('\n');
        const auto line = trim(remaining.substr(0,newline));
        remaining = newline == std::string_view::npos ? std::string_view{} : remaining.substr(newline+1);
        if (line.empty() || line.starts_with("//") || line.front() == ';' || line.front() == '#') continue;
        if (line.front() == '[') {
            if (line != "[ITEM]") throw CodecError("original_game_values_section_invalid");
            if (in_item) append(values,std::move(fields));
            if (values.entries.size() >= entry_limit) throw CodecError("original_game_values_entries_limit");
            fields.clear(); in_item = true; continue;
        }
        const auto separator = line.find_first_of("=:");
        if (!in_item || separator == std::string_view::npos) throw CodecError("original_game_value_field_invalid");
        const auto key = trim(line.substr(0,separator));
        if (key.empty() || key.size() > 128 || fields.size() >= 256 ||
            key.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != std::string_view::npos)
            throw CodecError("original_game_value_field_invalid");
        if (!fields.emplace(key,trim(line.substr(separator+1))).second) throw CodecError("original_game_value_field_duplicate");
    }
    if (!in_item) throw CodecError("original_game_values_empty");
    append(values,std::move(fields));
    values.decoded = std::move(decoded);
    return values;
}
OriginalGameValues load_original_game_values(const std::filesystem::path& path) {
    return parse_original_game_values(load_original_kpd(path,text_limit));
}
std::int32_t OriginalGameValues::require(std::int32_t index) const {
    const auto found = entries.find(index);
    if (found == entries.end()) throw CodecError("original_game_value_missing");
    return found->second.value;
}
}
