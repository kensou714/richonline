#include "original_options.hpp"
#include "../vendor/lzokay/lzokay.hpp"

#include <charconv>
#include <fstream>
#include <optional>

namespace richnet {
namespace {
constexpr std::size_t text_limit = 4U * 1024U * 1024U;
constexpr std::size_t maximum_decoded_limit = 64U * 1024U * 1024U;

std::size_t packed_limit_for(std::size_t decoded_limit) {
    if (decoded_limit == 0 || decoded_limit > maximum_decoded_limit)
        throw CodecError("original_kpd_limit_invalid");
    return lzokay::compress_worst_size(decoded_limit) + 9U;
}

std::string_view trim(std::string_view value) {
    constexpr std::string_view space = " \t\r";
    const auto begin = value.find_first_not_of(space);
    if (begin == std::string_view::npos) return {};
    return value.substr(begin, value.find_last_not_of(space) - begin + 1);
}

bool ascii_equal(std::string_view value, std::string_view expected) {
    if (value.size() != expected.size()) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto character = value[i];
        const auto lower = character >= 'A' && character <= 'Z' ? character + ('a' - 'A') : character;
        if (lower != expected[i]) return false;
    }
    return true;
}
}

Bytes decode_original_kpd(View data, std::size_t decoded_limit) {
    const auto packed_limit = packed_limit_for(decoded_limit);
    if (data.size() < 9) throw CodecError("original_kpd_header_truncated");
    if (data.size() > packed_limit) throw CodecError("original_kpd_size_invalid");
    Bytes decoded(data.begin() + 1, data.end());
    for (auto& byte : decoded) byte = static_cast<std::uint8_t>(byte - data.front());
    const auto text_size = read_le(View(decoded).first(4));
    const auto compressed_size = read_le(View(decoded).subspan(4, 4));
    if (text_size == 0 || text_size > decoded_limit || compressed_size != decoded.size() - 8)
        throw CodecError("original_kpd_lengths_invalid");
    Bytes text(text_size);
    std::size_t actual_size = 0;
    const auto result = lzokay::decompress(decoded.data() + 8, compressed_size,
                                         text.data(), text.size(), actual_size);
    if (result != lzokay::EResult::Success) throw CodecError("original_kpd_decompression_failed");
    if (actual_size != text.size()) throw CodecError("original_kpd_decoded_length_invalid");
    return text;
}

namespace {
std::int32_t parse_positive_option(std::string_view text, std::string_view section,
                                   std::string_view key, std::string_view error_prefix) {
    if (text.empty() || text.size() > text_limit || text.find('\0') != std::string_view::npos)
        throw CodecError("original_options_text_invalid");
    bool in_section = false;
    bool seen_section = false;
    std::optional<std::int32_t> option;
    const auto error = [error_prefix](std::string_view suffix) {
        return CodecError(std::string(error_prefix) + std::string(suffix));
    };
    while (!text.empty()) {
        const auto end = text.find('\n');
        const auto line = trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        if (line.empty() || line.front() == ';' || line.front() == '#' || line.starts_with("//")) continue;
        if (line.front() == '[') {
            if (line.back() != ']') throw CodecError("original_options_section_invalid");
            in_section = ascii_equal(trim(line.substr(1, line.size() - 2)), section);
            if (in_section && seen_section) throw error("_ambiguous");
            seen_section = seen_section || in_section;
            continue;
        }
        if (!in_section) continue;
        const auto separator = line.find_first_of("=:");
        if (separator == std::string_view::npos) {
            if (ascii_equal(line, key)) throw error("_invalid");
            continue;
        }
        if (!ascii_equal(trim(line.substr(0, separator)), key)) continue;
        if (option) throw error("_ambiguous");
        const auto value = trim(line.substr(separator + 1));
        if (value.empty() || value.find_first_not_of("0123456789") != std::string_view::npos)
            throw error("_invalid");
        std::int32_t parsed = 0;
        const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
        if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed < 1)
            throw error("_out_of_range");
        option = parsed;
    }
    if (!option) throw error("_missing");
    return *option;
}
}

std::int32_t parse_original_exchange_ratio(std::string_view text) {
    return parse_positive_option(text, "j_r", "ratio", "original_options_ratio");
}

std::int32_t parse_original_price_base(std::string_view text) {
    return parse_positive_option(text, "other", "pricebase", "original_options_price_base");
}

Bytes load_original_kpd(const std::filesystem::path& path, std::size_t decoded_limit) {
    const auto packed_limit = packed_limit_for(decoded_limit);
    std::ifstream input(path.c_str(), std::ios::binary | std::ios::ate);
    if (!input) throw CodecError("original_options_open_failed");
    const auto size = input.tellg();
    if (size < 0) throw CodecError("original_options_read_failed");
    if (static_cast<std::uintmax_t>(size) > packed_limit) throw CodecError("original_kpd_size_invalid");
    Bytes packed(static_cast<std::size_t>(size));
    input.seekg(0);
    if (!packed.empty() && !input.read(reinterpret_cast<char*>(packed.data()), static_cast<std::streamsize>(packed.size())))
        throw CodecError("original_options_read_failed");
    if (input.peek() != std::char_traits<char>::eof()) throw CodecError("original_options_read_failed");
    return decode_original_kpd(packed, decoded_limit);
}

std::int32_t load_original_exchange_ratio(const std::filesystem::path& path) {
    const auto text = load_original_kpd(path);
    return parse_original_exchange_ratio({reinterpret_cast<const char*>(text.data()), text.size()});
}

std::int32_t load_original_price_base(const std::filesystem::path& path) {
    const auto text = load_original_kpd(path);
    return parse_original_price_base({reinterpret_cast<const char*>(text.data()), text.size()});
}
}
