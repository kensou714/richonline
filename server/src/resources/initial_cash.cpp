#include "richonline_initial_cash.hpp"
#include "original_options.hpp"
#include <bit>
#include <charconv>
#include <limits>

namespace richnet {
namespace {
using Record = std::map<std::string, std::string, std::less<>>;
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
RichonlineInitialCash::RichonlineInitialCash(const std::filesystem::path& root)
    : props_(records(root / "Data" / "Prop.kpd", "[PROP]")) {}
std::uint32_t RichonlineInitialCash::apply(std::uint32_t initial, std::span<const std::uint32_t> equipment) const {
    if (initial > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("richonline_boss_cash_out_of_range");
    return equipment_cash(initial, equipment, props_);
}
}
