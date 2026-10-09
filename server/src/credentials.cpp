#include "credentials.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <bit>
#include <stdexcept>

namespace richnet {
namespace {
using Bytes = std::vector<std::uint8_t>;
class Sha256 {
public:
    Sha256() {
        if (BCryptOpenAlgorithmProvider(&handle_, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
            throw std::runtime_error("credential_provider_failed");
    }
    ~Sha256() { BCryptCloseAlgorithmProvider(handle_, 0); }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    Bytes derive(std::span<const std::uint8_t> password, std::span<const std::uint8_t> salt,
                 std::size_t length) const {
        Bytes result(length);
        if (BCryptDeriveKeyPBKDF2(handle_, const_cast<PUCHAR>(password.data()),
                                 static_cast<ULONG>(password.size()), const_cast<PUCHAR>(salt.data()),
                                 static_cast<ULONG>(salt.size()), 1, result.data(),
                                 static_cast<ULONG>(length), 0) < 0)
            throw std::runtime_error("credential_derivation_failed");
        return result;
    }
private:
    BCRYPT_ALG_HANDLE handle_{};
};

void salsa8(std::array<std::uint32_t, 16>& block) {
    auto x = block;
    for (int i = 0; i < 8; i += 2) {
        x[4] ^= std::rotl(x[0]+x[12],7); x[8] ^= std::rotl(x[4]+x[0],9);
        x[12] ^= std::rotl(x[8]+x[4],13); x[0] ^= std::rotl(x[12]+x[8],18);
        x[9] ^= std::rotl(x[5]+x[1],7); x[13] ^= std::rotl(x[9]+x[5],9);
        x[1] ^= std::rotl(x[13]+x[9],13); x[5] ^= std::rotl(x[1]+x[13],18);
        x[14] ^= std::rotl(x[10]+x[6],7); x[2] ^= std::rotl(x[14]+x[10],9);
        x[6] ^= std::rotl(x[2]+x[14],13); x[10] ^= std::rotl(x[6]+x[2],18);
        x[3] ^= std::rotl(x[15]+x[11],7); x[7] ^= std::rotl(x[3]+x[15],9);
        x[11] ^= std::rotl(x[7]+x[3],13); x[15] ^= std::rotl(x[11]+x[7],18);
        x[1] ^= std::rotl(x[0]+x[3],7); x[2] ^= std::rotl(x[1]+x[0],9);
        x[3] ^= std::rotl(x[2]+x[1],13); x[0] ^= std::rotl(x[3]+x[2],18);
        x[6] ^= std::rotl(x[5]+x[4],7); x[7] ^= std::rotl(x[6]+x[5],9);
        x[4] ^= std::rotl(x[7]+x[6],13); x[5] ^= std::rotl(x[4]+x[7],18);
        x[11] ^= std::rotl(x[10]+x[9],7); x[8] ^= std::rotl(x[11]+x[10],9);
        x[9] ^= std::rotl(x[8]+x[11],13); x[10] ^= std::rotl(x[9]+x[8],18);
        x[12] ^= std::rotl(x[15]+x[14],7); x[13] ^= std::rotl(x[12]+x[15],9);
        x[14] ^= std::rotl(x[13]+x[12],13); x[15] ^= std::rotl(x[14]+x[13],18);
    }
    for (std::size_t i = 0; i < 16; ++i) block[i] += x[i];
    SecureZeroMemory(x.data(), sizeof(x));
}

void block_mix(std::vector<std::uint32_t>& block, std::vector<std::uint32_t>& scratch,
               std::uint32_t r) {
    std::array<std::uint32_t, 16> x{};
    std::copy_n(block.end() - 16, 16, x.begin());
    for (std::size_t i = 0; i < 2U*r; ++i) {
        for (std::size_t k = 0; k < 16; ++k) x[k] ^= block[i*16+k];
        salsa8(x);
        const std::size_t offset = (i / 2 + (i % 2) * r) * 16;
        std::copy(x.begin(), x.end(), scratch.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    block.swap(scratch);
    SecureZeroMemory(x.data(), sizeof(x));
}

std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto b : bytes) { result += alphabet[b >> 4]; result += alphabet[b & 15]; }
    return result;
}
Bytes unhex(std::string_view text) {
    if (text.size() % 2 != 0) throw std::runtime_error("credential_verifier_invalid");
    Bytes bytes;
    auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c-'0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c-'a'+10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c-'A'+10);
        throw std::runtime_error("credential_verifier_invalid");
    };
    for (std::size_t i=0; i<text.size(); i+=2)
        bytes.push_back(static_cast<std::uint8_t>((nibble(text[i])<<4)|nibble(text[i+1])));
    return bytes;
}
}

std::vector<std::uint8_t> scrypt(std::span<const std::uint8_t> password,
                               std::span<const std::uint8_t> salt,
                               std::uint32_t n, std::uint32_t r,
                               std::uint32_t p, std::size_t length) {
    if (n < 2 || !std::has_single_bit(n) || r == 0 || p == 0 || r > 32 || p > 16 ||
        n > (1U << 20) || static_cast<std::uint64_t>(n)*r*128U > (256U << 20) ||
        length == 0 || length > 4096 || password.size() > 65536 || salt.size() > 65536)
        throw std::runtime_error("scrypt_parameters_invalid");
    Sha256 hash;
    auto bytes = hash.derive(password, salt, static_cast<std::size_t>(p)*r*128U);
    const std::size_t words = static_cast<std::size_t>(r)*32U;
    std::vector<std::uint32_t> block(words), scratch(words), memory(words*n);
    for (std::size_t part=0; part<p; ++part) {
        const std::size_t base=part*words*4;
        for (std::size_t i=0; i<words; ++i) {
            block[i]=0;
            for (std::size_t k=0; k<4; ++k)
                block[i] |= static_cast<std::uint32_t>(bytes[base+i*4+k]) << (k*8);
        }
        for (std::size_t i=0; i<n; ++i) {
            std::copy(block.begin(),block.end(),memory.begin()+static_cast<std::ptrdiff_t>(i*words));
            block_mix(block,scratch,r);
        }
        for (std::size_t i=0; i<n; ++i) {
            const std::size_t index=block[words-16] & (n-1);
            for (std::size_t k=0; k<words; ++k) block[k]^=memory[index*words+k];
            block_mix(block,scratch,r);
        }
        for (std::size_t i=0; i<words; ++i)
            for (std::size_t k=0; k<4; ++k)
                bytes[base+i*4+k]=static_cast<std::uint8_t>(block[i]>>(k*8));
    }
    auto result=hash.derive(password,bytes,length);
    SecureZeroMemory(memory.data(),memory.size()*sizeof(std::uint32_t));
    SecureZeroMemory(block.data(),block.size()*sizeof(std::uint32_t));
    SecureZeroMemory(scratch.data(),scratch.size()*sizeof(std::uint32_t));
    SecureZeroMemory(bytes.data(),bytes.size());
    return result;
}

CredentialVerifier create_verifier(std::span<const std::uint8_t> password) {
    std::array<std::uint8_t,16> salt{};
    if (BCryptGenRandom(nullptr,salt.data(),static_cast<ULONG>(salt.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)
        throw std::runtime_error("credential_random_failed");
    auto digest=scrypt(password,salt,16384,8,1,64);
    CredentialVerifier verifier{hex(salt),hex(digest)};
    SecureZeroMemory(digest.data(),digest.size());
    return verifier;
}

bool verify_password(std::span<const std::uint8_t> password,const CredentialVerifier& verifier) {
    const auto salt=unhex(verifier.salt);
    const auto expected=unhex(verifier.password_hash);
    if (salt.size()!=16 || expected.size()!=64) throw std::runtime_error("credential_verifier_invalid");
    auto actual=scrypt(password,salt,16384,8,1,64);
    std::uint8_t difference=0;
    for (std::size_t i=0; i<actual.size(); ++i) difference|=actual[i]^expected[i];
    SecureZeroMemory(actual.data(),actual.size());
    return difference==0;
}

std::string_view client_profile_name(ClientProfile profile) {
    switch (profile) {
        case ClientProfile::richonline: return "richonline";
        case ClientProfile::original: return "original";
    }
    throw std::runtime_error("client_profile_invalid");
}

ClientProfile parse_client_profile(std::string_view name) {
    if (name=="richonline") return ClientProfile::richonline;
    if (name=="original") return ClientProfile::original;
    throw std::runtime_error("client_profile_invalid");
}

std::vector<std::uint8_t> client_text(std::string_view utf8, ClientProfile profile) {
    if (utf8.empty() || utf8.size()>4096 || utf8.find('\0')!=std::string_view::npos)
        throw std::runtime_error("client_text_invalid");
    const int length=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,utf8.data(),static_cast<int>(utf8.size()),nullptr,0);
    if (length<=0) throw std::runtime_error("client_text_invalid_utf8");
    std::wstring wide(static_cast<std::size_t>(length),L'\0');
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,utf8.data(),static_cast<int>(utf8.size()),wide.data(),length);
    BOOL used_default=FALSE;
    const UINT codepage=profile==ClientProfile::original?936:950;
    const char* encoding_error=profile==ClientProfile::original?"client_text_not_gbk":"client_text_not_big5";
    const int bytes=WideCharToMultiByte(codepage,WC_NO_BEST_FIT_CHARS,wide.data(),length,nullptr,0,nullptr,&used_default);
    if (bytes<=0 || used_default) throw std::runtime_error(encoding_error);
    Bytes result(static_cast<std::size_t>(bytes));
    WideCharToMultiByte(codepage,WC_NO_BEST_FIT_CHARS,wide.data(),length,reinterpret_cast<char*>(result.data()),bytes,nullptr,&used_default);
    if (used_default) throw std::runtime_error(encoding_error);
    return result;
}
}
