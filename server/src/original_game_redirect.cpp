#include "original_game_redirect.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace richnet {

Frame encode_original_game_redirect(const OriginalGameRedirect& redirect) {
    if (redirect.endpoint.port == 0) throw CodecError("original_game_redirect_port_invalid");
    if (redirect.token_a > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("original_game_redirect_token_a_out_of_range");
    Bytes payload(redirect.endpoint.address.begin(), redirect.endpoint.address.end());
    append_le(payload, redirect.endpoint.port, 2);
    append_le(payload, redirect.token_a, 4);
    append_le(payload, redirect.token_b, 4);
    append_le(payload, redirect.token_c, 4);
    return {22, std::move(payload)};
}

GameAdmission original_expected_admission(OriginalAdmissionIdentity identity,
                                         const OriginalGameRedirect& redirect) {
    if (redirect.endpoint.port == 0) throw CodecError("original_game_redirect_port_invalid");
    if (redirect.token_a > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
        throw CodecError("original_game_redirect_token_a_out_of_range");
    constexpr auto maximum_id = std::numeric_limits<std::int16_t>::max();
    if (identity.user_id > maximum_id)
        throw CodecError("original_game_admission_identity_out_of_range");
    Bytes echoed_tokens;
    append_le(echoed_tokens, redirect.token_b, 4);
    append_le(echoed_tokens, redirect.token_c, 4);
    GameAdmission admission{identity.room_id, identity.game_id, identity.user_id, {}, redirect.token_a, {}};
    std::copy(echoed_tokens.begin(), echoed_tokens.end(), admission.opaque8.begin());
    // Original C2S0 construction explicitly writes +24/+28 as zero; see GAME-LOBBY-ENTRY.md.
    admission.legacy_fields = std::array<std::uint32_t, 2>{0, 0};
    return admission;
}

OriginalGameRedirect original_redirect_with_random_tokens(OriginalGameEndpoint endpoint) {
    if (endpoint.port == 0) throw CodecError("original_game_redirect_port_invalid");
    std::array<std::uint8_t, 12> entropy;
    const auto status = BCryptGenRandom(nullptr, entropy.data(), static_cast<ULONG>(entropy.size()),
                                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) throw CodecError("original_game_redirect_random_generation_failed");
    const View tokens(entropy);
    return {endpoint, read_le(tokens.subspan(0, 4)) & 0x7fffffffU, read_le(tokens.subspan(4, 4)),
            read_le(tokens.subspan(8, 4))};
}

}
