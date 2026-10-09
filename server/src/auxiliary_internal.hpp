#pragma once

#include "auxiliary.hpp"
#include "codec.hpp"
#include <optional>

namespace richnet::auxiliary_detail {
struct Response {
    Bytes bytes;
    std::string_view reason;
    std::optional<std::uint32_t> type;
};
std::optional<Response> response(AuxiliaryKind kind, View input, const AuxiliaryOptions& options);
}
