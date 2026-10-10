#pragma once
#include "storage.hpp"

namespace richnet {
class LuaServer;
struct RichonlineMallCompatibilityPolicy {
    // NEW77 consumes these DWORDs only to advance the cursor; neither reaches
    // any business callback. Deliberate compatibility padding may therefore be0.
    std::uint32_t ignored_word0,ignored_word2;
    // NEW UI207 consumes this generic-error result and clears purchase pending.
    std::int32_t refused;
    std::string evidence;
    RichonlineInventoryDateVersion date_version=RichonlineInventoryDateVersion::original_2005;
    // Filled by the adapter only after verifying the actual selected client.
    std::string verified_client_compatibility_id{};
};
struct RichonlineMallServiceReply {
    std::vector<Frame> frames;
    std::string diagnostic;
    // Shared adapter must emit an authoritative profile19 from this CURRENT row
    // before77: the ordinary purchase callback does not debit local wallets.
    std::optional<nlohmann::json> role_refresh;
    //213 applies a client-side debit: its authoritative refresh must be AFTER.
    bool role_refresh_after_frames=false;
    bool activation_committed=false;
};
class RichonlineMallService final {
public:
    RichonlineMallService(const RichonlineMallCatalog& catalog,std::string session_operation_prefix,
        RichonlineMallCompatibilityPolicy policy);
    std::optional<RichonlineMallServiceReply> request(Storage& storage,const std::string& username,
        std::int64_t role_id,const Frame& request,std::int64_t unix_now,
        const RichonlineMallActivationPrepare& prepare_activation={});
private:
    const RichonlineMallCatalog& catalog_;
    std::string operation_prefix_;
    RichonlineMallCompatibilityPolicy policy_;
    std::int32_t operation_{};
    std::uint64_t sequence_{};
    std::shared_ptr<LuaServer> script_;
};
}
