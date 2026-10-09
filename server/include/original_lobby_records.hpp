#pragma once

#include "original_lobby_adapter.hpp"

namespace richnet {
Bytes original_role_record(const nlohmann::json& role, const OriginalLobbyPolicy& policy);
Bytes original_profile_record(const nlohmann::json& role, const OriginalLobbyPolicy& policy);
}
