#pragma once

#include "richonline_auxiliary.hpp"
#include <filesystem>
#include <mutex>
#include <string>

struct sqlite3;

namespace richnet {
struct RichonlineIntroSnapshot {
    std::int64_t role_id;
    std::string text_utf8;
    std::int64_t revision;
};

// Opens the existing NEW account database; never creates an account database or
// writes authentication fields. The caller must authenticate all mutation APIs.
class RichonlineAuxiliaryStore final {
public:
    explicit RichonlineAuxiliaryStore(const std::filesystem::path& database);
    ~RichonlineAuxiliaryStore();
    RichonlineAuxiliaryStore(const RichonlineAuxiliaryStore&) = delete;
    RichonlineAuxiliaryStore& operator=(const RichonlineAuxiliaryStore&) = delete;
    RichonlineIntroSnapshot introduction(const RichonlineAuxiliaryName& name);
    std::optional<Bytes> intro_response(View request);
    RichonlineIntroSnapshot save_introduction(const std::string& authenticated_username,
        std::int64_t role_id, const std::string& text_utf8, std::int64_t expected_revision,
        const std::string& audit_reason);
private:
    sqlite3* db_{};
    std::mutex mutex_;
};
}
