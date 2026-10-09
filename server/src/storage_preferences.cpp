#include "storage_detail.hpp"

#include <algorithm>
#include <charconv>
#include <limits>

namespace richnet {
using namespace storage_detail;

std::optional<std::string> Storage::preferences_for_username(const std::string& username) {
    const std::lock_guard lock(mutex_);
    Statement select(db_,"SELECT setting_text FROM accounts WHERE username=?");
    select.bind(1,username);
    if (!select.row()) throw StorageError("account_not_found");
    const auto value=select.record().at("setting_text");
    if (value.is_null()) return std::nullopt;
    return value.get<std::string>();
}

void Storage::save_preferences(const std::string& username, std::span<const std::uint8_t> payload) {
    if (payload.size()<2 || payload.size()>11 || payload.back()!=0)
        throw StorageError("preference_length_or_terminator_invalid");
    const auto digits=payload.first(payload.size()-1);
    if (std::any_of(digits.begin(),digits.end(),[](std::uint8_t value) { return value<'0' || value>'9'; }))
        throw StorageError("preference_not_decimal");
    const std::string setting(digits.begin(),digits.end());
    std::uint32_t mask=0;
    const auto parsed=std::from_chars(setting.data(),setting.data()+setting.size(),mask);
    if (parsed.ec!=std::errc{} || mask>static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw StorageError("preference_out_of_range");

    const std::lock_guard lock(mutex_);
    Transaction transaction(db_);
    Statement select(db_,"SELECT setting_text FROM accounts WHERE username=?");
    select.bind(1,username);
    if (!select.row()) throw StorageError("account_not_found");
    const auto current=select.record().at("setting_text");
    if (current!=setting) {
        Statement update(db_,"UPDATE accounts SET setting_text=? WHERE username=?");
        update.bind(1,setting); update.bind(2,username); update.row();
        Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(0,?,'setting_text',?,?,'lobby','client preferences','')");
        audit.bind(1,username); audit.bind(2,current.is_null()?std::string{}:current.get<std::string>());
        audit.bind(3,setting); audit.row();
    }
    transaction.commit();
}
}
