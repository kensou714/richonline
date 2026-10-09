#include "storage_detail.hpp"

namespace richnet {
using namespace storage_detail;
namespace storage_detail {
nlohmann::json default_settings() {
    return {{"version",1},{"announcement",""},{"registration_enabled",true},{"tutorial_enabled",false},
        {"default_role",{{"model",0},{"level",6},{"experience",700},{"mpoints",10000.0},
                         {"gold",10000.0},{"bank",0.0},{"vip_level",0}}},
        {"max_building_skills",{7,7,7,7,7,7,7,7,7,7}}};
}
void validate_settings(const nlohmann::json& settings, ClientProfile profile) {
    require_keys(settings,{"version","announcement","registration_enabled","tutorial_enabled","default_role","max_building_skills"});
    if (settings.at("version")!=1 || !settings.at("registration_enabled").is_boolean() ||
        !settings.at("tutorial_enabled").is_boolean()) throw StorageError("settings_type_invalid");
    const auto announcement=settings.at("announcement").get<std::string>();
    if (announcement.size()>1024 || announcement.find('\0')!=std::string::npos) throw StorageError("announcement_invalid");
    const auto& defaults=settings.at("default_role");
    require_keys(defaults,{"model","level","experience","mpoints","gold","bank","vip_level"});
    auto role=defaults;
    role["name"]="default"; role["coins"]=defaults.at("mpoints");
    for (const auto* field:{"wins","losses","draws","escapes","purchase_score"}) role[field]=0;
    validate_role(role,profile);
    const auto& skills=settings.at("max_building_skills");
    if (!skills.is_array() || skills.size()!=10) throw StorageError("building_skills_invalid");
    for (const auto& skill:skills)
        if (!skill.is_number_integer() || skill<0 || skill>7) throw StorageError("building_skills_invalid");
}
}

nlohmann::json Storage::get_config() {
    Statement statement(db_,"SELECT revision,settings FROM native_settings WHERE id=1");
    if (!statement.row()) throw StorageError("settings_missing");
    return {{"revision",statement.integer(0)},{"settings",nlohmann::json::parse(statement.text(1))}};
}
nlohmann::json Storage::update_config(const nlohmann::json& payload) {
    require_keys(payload,{"expectedRevision","settings"});
    const auto& revision=payload.at("expectedRevision");
    if (!revision.is_number_integer() || revision<1 || revision>=2147483647) throw StorageError("settings_revision_invalid");
    const auto& settings=payload.at("settings");
    validate_settings(settings,profile_);
    Transaction transaction(db_);
    const auto current=get_config();
    if (revision!=current.at("revision")) throw StorageError("settings_changed_refresh_required");
    const auto next_revision=revision.get<std::int64_t>()+1;
    Statement update(db_,"UPDATE native_settings SET revision=?,settings=? WHERE id=1");
    update.bind(1,next_revision); update.bind(2,settings.dump()); update.row();
    Statement audit(db_,"INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) VALUES(0,'','settings',?,?,'native-admin','administrator configuration edit','')");
    audit.bind(1,current.at("settings").dump()); audit.bind(2,settings.dump()); audit.row();
    transaction.commit();
    return {{"settings",settings},{"revision",next_revision}};
}
}
