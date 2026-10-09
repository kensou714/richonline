#pragma once

// 凭据与文本边界：服务端口令校验使用 scrypt，客户端文字编码按配置版本选择。

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace richnet {
enum class ClientProfile { richonline, original };
std::string_view client_profile_name(ClientProfile profile);
ClientProfile parse_client_profile(std::string_view name);
struct CredentialVerifier {
    std::string salt;
    std::string password_hash;
};

std::vector<std::uint8_t> scrypt(std::span<const std::uint8_t> password,
                               std::span<const std::uint8_t> salt,
                               std::uint32_t n, std::uint32_t r,
                               std::uint32_t p, std::size_t length);
CredentialVerifier create_verifier(std::span<const std::uint8_t> password);
bool verify_password(std::span<const std::uint8_t> password, const CredentialVerifier& verifier);
// 新版输出 Big5（代码页 950）；保留的旧版配置输出 GBK（代码页 936）。
std::vector<std::uint8_t> client_text(std::string_view utf8, ClientProfile profile = ClientProfile::richonline);
}
