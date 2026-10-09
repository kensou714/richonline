#include "richonline_auxiliary.hpp"

#include <algorithm>
#include <bit>

namespace richnet {
namespace {
void magic_prefix(View input) {
    if ((!input.empty() && input[0] != 13) || (input.size() >= 2 && input[1] != 10))
        throw CodecError("richonline_auxiliary_bad_magic");
}

RichonlineAuxiliaryName name_at(View input, std::size_t offset) {
    RichonlineAuxiliaryName name;
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(offset), name.size(), name.begin());
    return name;
}

void append_name(Bytes& body, const RichonlineAuxiliaryName& name) {
    // All 32 bytes are present on the wire, including names filling the field.
    body.insert(body.end(), name.begin(), name.end());
}

Bytes response(std::uint32_t type, const Bytes& body) {
    Bytes result;
    result.reserve(8 + body.size());
    append_le(result, type, 4);
    append_le(result, static_cast<std::uint32_t>(body.size()), 4);
    result.insert(result.end(), body.begin(), body.end());
    return result;
}

void append_rank(Bytes& body, const RichonlineRankValue& row) {
    append_name(body, row.name);
    append_le(body, static_cast<std::uint32_t>(row.value), 4);
}

void validate_display_text(View text) {
    for (std::size_t index = 0; index < text.size(); ++index) {
        if (text[index] == 0 || text[index] == 0x80)
            throw CodecError("richonline_auxiliary_text_invalid_byte");
        // 6BEFB0 treats every high-bit lead as a two-byte display unit. A lone
        // lead or 0x80 makes that client loop read outside text or stop advancing.
        if (text[index] > 0x80) {
            if (++index == text.size() || text[index] == 0)
                throw CodecError("richonline_auxiliary_text_incomplete_pair");
        }
    }
}
}

std::optional<RichonlineInquiryRequest> decode_richonline_inquiry_request(View input) {
    magic_prefix(input);
    if (input.size() < 6) return std::nullopt;
    const auto type = read_le(input.subspan(2, 4));
    if (type > 2) throw CodecError("richonline_inquiry_wire_type_unknown");
    const std::size_t size = type == 1 ? 10 : 42;
    if (input.size() > size) throw CodecError("richonline_inquiry_trailing_bytes");
    if (input.size() < size) return std::nullopt;
    const auto category = std::bit_cast<std::int32_t>(read_le(input.subspan(6, 4)));
    return RichonlineInquiryRequest{static_cast<RichonlineInquiryType>(type), category,
        type == 1 ? std::nullopt : std::optional{name_at(input, 10)}};
}

std::optional<RichonlineAuxiliaryName> decode_richonline_intro_request(View input) {
    magic_prefix(input);
    if (input.size() < 6) return std::nullopt;
    if (read_le(input.subspan(2, 4)) != 0) throw CodecError("richonline_intro_wire_type_unknown");
    if (input.size() < 10) return std::nullopt;
    if (read_le(input.subspan(6, 4)) != 32) throw CodecError("richonline_intro_name_length_invalid");
    if (input.size() > 42) throw CodecError("richonline_intro_trailing_bytes");
    if (input.size() < 42) return std::nullopt;
    return name_at(input, 10);
}

std::optional<std::uint32_t> decode_richonline_aux_channel_request(View input) {
    magic_prefix(input);
    if (input.size() < 6) return std::nullopt;
    if (input.size() != 6) throw CodecError("richonline_aux_channel_trailing_bytes");
    const auto type = read_le(input.subspan(2, 4));
    if (type > 1) throw CodecError("richonline_aux_channel_wire_type_unknown");
    return type;
}

Bytes encode_richonline_named_ranking(std::int32_t self_rank,
    const RichonlineRankValue& self, std::span<const RichonlineRankValue> rows) {
    if (rows.size() > 100) throw CodecError("richonline_inquiry_row_limit");
    Bytes body;
    append_le(body, static_cast<std::uint32_t>(self_rank), 4);
    append_rank(body, self);
    append_le(body, static_cast<std::uint32_t>(rows.size()), 4);
    for (const auto& row : rows) append_rank(body, row);
    return response(0, body);
}

Bytes encode_richonline_category_ranking(std::span<const RichonlineRankColumns> rows) {
    if (rows.size() > 100) throw CodecError("richonline_inquiry_row_limit");
    Bytes body;
    append_le(body, static_cast<std::uint32_t>(rows.size()), 4);
    for (const auto& row : rows) {
        append_name(body, row.name);
        for (const auto value : row.columns) append_le(body, static_cast<std::uint32_t>(value), 4);
    }
    return response(1, body);
}

Bytes encode_richonline_rank_search(std::int32_t rank_or_not_found) {
    // 755DE0 renders only positive ranks <=10000, or -1 (not found).
    if (rank_or_not_found != -1 && (rank_or_not_found < 1 || rank_or_not_found > 10000))
        throw CodecError("richonline_inquiry_search_result_invalid");
    Bytes body;
    append_le(body, static_cast<std::uint32_t>(rank_or_not_found), 4);
    return response(2, body);
}

Bytes encode_richonline_intro(const RichonlineAuxiliaryName& name, View text) {
    if (text.size() > 400) throw CodecError("richonline_intro_text_too_long");
    validate_display_text(text);
    Bytes body;
    append_name(body, name);
    body.insert(body.end(), text.begin(), text.end());
    return response(0, body);
}

RichonlineAuxiliaryName richonline_auxiliary_name(std::string_view encoded_name) {
    if (encoded_name.size() > 32 || encoded_name.find('\0') != std::string_view::npos)
        throw CodecError("richonline_auxiliary_name_invalid");
    RichonlineAuxiliaryName result{};
    std::copy(encoded_name.begin(), encoded_name.end(), result.begin());
    return result;
}
}
