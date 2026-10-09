#include "richonline_inventory_date.hpp"
#include <limits>

namespace richnet {
namespace {
constexpr std::uint32_t date_mask=0x3ffe0000U;
int epoch(RichonlineInventoryDateVersion version) {
    if(version!=RichonlineInventoryDateVersion::original_2005&&version!=RichonlineInventoryDateVersion::compat_2021_v1)
        throw CodecError("inventory_date_version_invalid");
    return static_cast<int>(version);
}
std::chrono::year_month_day calendar(const RichonlineInventoryDate& value) {
    if(value.year<1||value.year>32767||value.month<1||value.month>12||value.day<1||value.day>31)
        throw CodecError("inventory_date_calendar_invalid");
    const std::chrono::year_month_day date{std::chrono::year{value.year},std::chrono::month{value.month},std::chrono::day{value.day}};
    if(!date.ok())throw CodecError("inventory_date_calendar_invalid");return date;
}
}
std::uint32_t encode_richonline_inventory_date(std::uint32_t key,const std::optional<RichonlineInventoryDate>& date,
    RichonlineInventoryDateVersion version) {
    const auto base=epoch(version);
    if((key&4095U)==0||(key&0x80000000U)!=0)throw CodecError("inventory_date_key_invalid");
    auto result=key&~date_mask;
    if(!date)return result;
    static_cast<void>(calendar(*date));
    if(date->year<base||date->year>base+15)throw CodecError("inventory_date_year_unrepresentable");
    result|=static_cast<std::uint32_t>(date->year-base)<<26U;result|=date->month<<22U;result|=date->day<<17U;return result;
}
std::optional<RichonlineInventoryDate> decode_richonline_inventory_date(std::uint32_t key,RichonlineInventoryDateVersion version) {
    const auto base=epoch(version);
    if((key&4095U)==0||(key&0x80000000U)!=0)throw CodecError("inventory_date_key_invalid");
    if((key&date_mask)==0)return {};
    RichonlineInventoryDate value{base+static_cast<int>((key>>26U)&15U),(key>>22U)&15U,(key>>17U)&31U};
    static_cast<void>(calendar(value));return value;
}
RichonlineInventoryDate richonline_inventory_utc_date(std::int64_t unix_time) {
    // Limit before constructing chrono::year: the type stores a signed16 year.
    constexpr std::int64_t upper=253402300799LL; //9999-12-31T23:59:59Z
    if(unix_time<0||unix_time>upper)throw CodecError("inventory_date_unix_time_invalid");
    const std::chrono::year_month_day date{std::chrono::floor<std::chrono::days>(std::chrono::sys_seconds{std::chrono::seconds{unix_time}})};
    return {static_cast<int>(date.year()),static_cast<unsigned>(date.month()),static_cast<unsigned>(date.day())};
}
std::uint32_t richonline_inventory_key_from_expiry(std::uint32_t key,std::int64_t expiry,RichonlineInventoryDateVersion version) {
    if(expiry==0)return encode_richonline_inventory_date(key,{},version);
    return encode_richonline_inventory_date(key,richonline_inventory_utc_date(expiry),version);
}
std::int64_t richonline_inventory_calendar_expiry(std::int64_t now,std::uint32_t years,std::uint32_t months,std::uint32_t days) {
    const auto value=richonline_inventory_utc_date(now);
    const auto original=calendar(value);
    // Resource values are not allowed to overflow chrono or the protocol era.
    const auto total_months=static_cast<std::uint64_t>(years)*12U+months;
    if(total_months>1200U||days>36600U)throw CodecError("inventory_date_term_invalid");
    const auto shifted=original.year()/original.month()+std::chrono::months{static_cast<int>(total_months)};
    const std::chrono::year_month_day_last end{shifted.year(),std::chrono::month_day_last{shifted.month()}};
    const auto chosen_day=std::min(static_cast<unsigned>(original.day()),static_cast<unsigned>(end.day()));
    const std::chrono::year_month_day target{shifted.year(),shifted.month(),std::chrono::day{chosen_day}};
    const auto midnight=std::chrono::sys_days{target}+std::chrono::days{static_cast<int>(days)};
    const auto remainder=std::chrono::seconds{now}-std::chrono::floor<std::chrono::days>(std::chrono::seconds{now});
    const auto result=std::chrono::duration_cast<std::chrono::seconds>(midnight.time_since_epoch()+remainder).count();
    static_cast<void>(richonline_inventory_utc_date(result));return result;
}
}
