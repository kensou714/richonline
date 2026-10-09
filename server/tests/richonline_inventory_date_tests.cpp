#include "richonline_inventory_date.hpp"
#include <iostream>

namespace {
using namespace richnet;
void check(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
template<class Action>void rejects(Action action,const char* reason){try{action();}catch(const CodecError& error){check(std::string_view(error.what())==reason,"wrong rejection");return;}throw std::runtime_error("expected rejection");}
std::int64_t unix_time(int y,unsigned m,unsigned d){return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::sys_days{std::chrono::year{y}/std::chrono::month{m}/std::chrono::day{d}}.time_since_epoch()).count();}
}
int main(){try{
    const auto old=RichonlineInventoryDateVersion::original_2005,modern=RichonlineInventoryDateVersion::compat_2021_v1;
    for(const auto version:{old,modern}) {
        const auto base=static_cast<int>(version);
        for(int year=base;year<=base+15;++year)for(unsigned month=1;month<=12;++month)for(unsigned day=1;day<=31;++day) {
            if(!(std::chrono::year{year}/std::chrono::month{month}/std::chrono::day{day}).ok())continue;
            const RichonlineInventoryDate date{year,month,day};const auto key=encode_richonline_inventory_date(0x4001100dU,date,version);
            check(decode_richonline_inventory_date(key,version)==date,"date roundtrip failed");
            check((key&0x4001ffffU)==0x4001100dU,"product/currency/state flags changed");
        }
    }
    rejects([&]{encode_richonline_inventory_date(13,RichonlineInventoryDate{2026,10,9},old);},"inventory_date_year_unrepresentable");
    rejects([&]{encode_richonline_inventory_date(13,RichonlineInventoryDate{2037,1,1},modern);},"inventory_date_year_unrepresentable");
    rejects([&]{encode_richonline_inventory_date(13,RichonlineInventoryDate{2026,2,29},modern);},"inventory_date_calendar_invalid");
    rejects([&]{decode_richonline_inventory_date(13U|(15U<<22U),modern);},"inventory_date_calendar_invalid");
    check(!decode_richonline_inventory_date(0x100d,modern),"zero-date sentinel lost");
    check(richonline_inventory_key_from_expiry(0x3442100dU,0,modern)==0x100d,"permanent left stale date");
    const auto now=unix_time(2026,10,9)+23*3600+59*60;
    const auto expiry=richonline_inventory_calendar_expiry(now,1,0,0);
    check(expiry==unix_time(2027,10,9)+23*3600+59*60,"year term lost time of day");
    const auto key=richonline_inventory_key_from_expiry(0x100d,expiry,modern);
    check(decode_richonline_inventory_date(key,modern)==RichonlineInventoryDate{2027,10,9},"2027 expiry failed");
    check(richonline_inventory_calendar_expiry(unix_time(2024,2,29),1,0,0)==unix_time(2025,2,28),"leap anniversary policy");
    check(richonline_inventory_calendar_expiry(unix_time(2026,1,31),0,1,2)==unix_time(2026,3,2),"month clamp then days policy");
    rejects([&]{richonline_inventory_calendar_expiry(now,101,0,0);},"inventory_date_term_invalid");
    rejects([&]{richonline_inventory_utc_date(-1);},"inventory_date_unix_time_invalid");
    std::cout<<"PASS explicit2005/2021 date epochs, exhaustive Gregorian roundtrip, metadata preservation, overflow rejection, UTC and calendar term policy\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
