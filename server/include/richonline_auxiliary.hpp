#pragma once

#include "codec.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace richnet {

using RichonlineAuxiliaryName = std::array<std::uint8_t, 32>;

enum class RichonlineInquiryType : std::uint32_t {
    named_category = 0,
    category_table = 1,
    search_rank = 2,
};

struct RichonlineInquiryRequest {
    RichonlineInquiryType type;
    std::int32_t category;
    std::optional<RichonlineAuxiliaryName> name;
};

// These services have their own framing. They are not lobby Frame packets.
std::optional<RichonlineInquiryRequest> decode_richonline_inquiry_request(View input);
std::optional<RichonlineAuxiliaryName> decode_richonline_intro_request(View input);
std::optional<std::uint32_t> decode_richonline_aux_channel_request(View input);

struct RichonlineRankValue {
    RichonlineAuxiliaryName name;
    std::int32_t value;
};

struct RichonlineRankColumns {
    RichonlineAuxiliaryName name;
    // Wire +32/+36/+40. UI placement is proven; business column labels are not.
    std::array<std::int32_t, 3> columns;
};

Bytes encode_richonline_named_ranking(std::int32_t self_rank,
    const RichonlineRankValue& self, std::span<const RichonlineRankValue> rows);
Bytes encode_richonline_category_ranking(std::span<const RichonlineRankColumns> rows);
Bytes encode_richonline_rank_search(std::int32_t rank_or_not_found);
Bytes encode_richonline_intro(const RichonlineAuxiliaryName& name, View text);

// A bounded string constructor: remaining bytes are defined NUL string padding.
RichonlineAuxiliaryName richonline_auxiliary_name(std::string_view encoded_name);

}
