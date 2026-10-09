#pragma once
#include "codec.hpp"
#include <chrono>
#include <optional>
#include <string_view>

namespace richnet {
enum class RichonlineInventoryDateVersion : std::uint16_t { original_2005=2005,compat_2021_v1=2021 };
constexpr std::string_view richonline_inventory_compatibility_id="richonline-inventory-date-2021-v1";
struct RichonlineInventoryDate { int year; unsigned month,day; bool operator==(const RichonlineInventoryDate&) const=default; };
// All epoch selection is explicit. There is no truncation of unrepresentable years.
std::uint32_t encode_richonline_inventory_date(std::uint32_t key,const std::optional<RichonlineInventoryDate>& date,
    RichonlineInventoryDateVersion version);
std::optional<RichonlineInventoryDate> decode_richonline_inventory_date(std::uint32_t key,RichonlineInventoryDateVersion version);
RichonlineInventoryDate richonline_inventory_utc_date(std::int64_t unix_time);
std::uint32_t richonline_inventory_key_from_expiry(std::uint32_t key,std::int64_t expires_at,
    RichonlineInventoryDateVersion version);
// Calendar-term compatibility policy: add whole months/years with end-of-month
// clamping, then whole days; preserve the original UTC time of day.
std::int64_t richonline_inventory_calendar_expiry(std::int64_t unix_now,std::uint32_t years,std::uint32_t months,std::uint32_t days);
}
