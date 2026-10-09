#pragma once

#include "richonline_auxiliary_store.hpp"
#include "storage.hpp"

namespace richnet {
struct RichonlineIntroSaveResult {
    std::vector<Frame> responses;
    std::string rejection;
};
// NEW wire50 uses the authenticated selected role, never an identity in payload.
// A successful commit has no lobby ACK; the intro TCP service reads the result.
RichonlineIntroSaveResult richonline_intro_request(Storage& accounts,
    RichonlineAuxiliaryStore& introductions, const std::string& username,
    std::uint32_t role_id, const Frame& request);
}
