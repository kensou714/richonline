#include "storage_detail.hpp"

namespace richnet {
using namespace storage_detail;
nlohmann::json Storage::select_model(const std::string& username, std::int64_t role_id, std::uint32_t model) {
    const std::lock_guard lock(mutex_);
    if (model > (profile_ == ClientProfile::richonline ? 8U : 4U)) throw StorageError("model_selection_invalid");
    Transaction transaction(db_);
    Statement select(db_, "SELECT * FROM roles WHERE role_id=? AND username=?");
    select.bind(1, role_id); select.bind(2, username);
    if (!select.row()) throw StorageError("model_role_not_owned");
    auto role = select.record();
    if (role.at("model") == model) {
        transaction.commit();
        return role;
    }
    Statement write(db_, "UPDATE roles SET model=? WHERE role_id=? AND username=?");
    write.bind(1, model); write.bind(2, role_id); write.bind(3, username); write.row();
    Statement audit(db_, "INSERT INTO audit(role_id,username,field,old_value,new_value,source,reason,operation_id) "
        "VALUES(?,?,'model',?,?,'native-lobby','client model selection','')");
    audit.bind(1, role_id); audit.bind(2, username); audit.bind(3, role.at("model").dump());
    audit.bind(4, nlohmann::json(model).dump()); audit.row();
    role["model"] = model;
    transaction.commit();
    return role;
}
}
