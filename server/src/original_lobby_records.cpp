#include "original_lobby_records.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>

namespace richnet {
namespace {
using Json = nlohmann::json;
void put_integer(Bytes& data, std::size_t offset, const Json& value) {
    if (!value.is_number_integer() || value < 0 || value > std::numeric_limits<std::int32_t>::max())
        throw CodecError("original_role_integer_invalid");
    const auto number = value.get<std::uint32_t>();
    for (std::size_t i = 0; i < 4; ++i) data.at(offset + i) = static_cast<std::uint8_t>(number >> (i * 8));
}
void put_balance(Bytes& data, std::size_t offset, const Json& value) {
    if (!value.is_number() || !std::isfinite(value.get<double>()) || value.get<double>() < 0)
        throw CodecError("original_role_balance_invalid");
    const auto bits = std::bit_cast<std::uint64_t>(value.get<double>());
    for (std::size_t i = 0; i < 8; ++i) data.at(offset + i) = static_cast<std::uint8_t>(bits >> (i * 8));
}
void put_name(Bytes& data, std::size_t offset, const Json& value) {
    const auto encoded = client_text(value.get<std::string>(), ClientProfile::original);
    if (encoded.size() >= 32) throw CodecError("original_role_name_too_long");
    std::fill_n(data.begin() + static_cast<std::ptrdiff_t>(offset), 32, 0);
    std::copy(encoded.begin(), encoded.end(), data.begin() + static_cast<std::ptrdiff_t>(offset));
}
}
Bytes original_role_record(const Json& role, const OriginalLobbyPolicy& policy) {
    auto data = policy.role_template;
    for (const auto& [offset, field] : std::initializer_list<std::pair<std::size_t, const char*>>{
             {0,"role_id"},{4,"model"},{8,"purchase_score"},{12,"level"},{16,"wins"},{20,"losses"},{24,"draws"},{44,"experience"}})
        put_integer(data, offset, role.at(field));
    put_balance(data, 36, role.at("gold"));
    put_name(data, 48, role.at("name"));
    return data;
}
Bytes original_profile_record(const Json& role, const OriginalLobbyPolicy& policy) {
    auto data = policy.profile_template;
    for (const auto& [offset, field] : std::initializer_list<std::pair<std::size_t, const char*>>{
             {0,"role_id"},{24,"wins"},{28,"losses"},{32,"draws"},{40,"model"},{52,"level"},{56,"vip_level"},
             {72,"purchase_score"},{100,"experience"},{104,"escapes"}})
        put_integer(data, offset, role.at(field));
    put_integer(data, 8, policy.room_id);
    std::fill_n(data.begin() + 12, 4, 0xff);
    put_balance(data, 76, role.at("coins")); put_balance(data, 84, role.at("gold")); put_balance(data, 92, role.at("bank"));
    put_name(data, 108, role.at("name"));
    return data;
}
}
