#pragma once

#include "game_admission.hpp"

namespace richnet {

struct OriginalGameEndpoint {
    std::array<std::uint8_t, 4> address;
    std::uint16_t port;
};

struct OriginalGameRedirect {
    OriginalGameEndpoint endpoint;
    std::uint32_t token_a;
    std::uint32_t token_b;
    std::uint32_t token_c;
};

struct OriginalAdmissionIdentity {
    std::uint32_t room_id;
    std::uint32_t game_id;
    std::uint32_t user_id;
};

Frame encode_original_game_redirect(const OriginalGameRedirect& redirect);
GameAdmission original_expected_admission(OriginalAdmissionIdentity identity,
                                         const OriginalGameRedirect& redirect);
OriginalGameRedirect original_redirect_with_random_tokens(OriginalGameEndpoint endpoint);

}
