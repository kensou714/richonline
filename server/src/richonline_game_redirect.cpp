#include "richonline_game_redirect.hpp"

#include <utility>

namespace richnet {
Frame encode_richonline_game_redirect(const RichonlineGameRedirect& redirect) {
    if (redirect.port == 0) throw CodecError("richonline_game_redirect_port_invalid");
    Bytes payload(redirect.address.begin(), redirect.address.end());
    append_le(payload, redirect.port, 2);
    append_le(payload, redirect.extra, 4);
    payload.insert(payload.end(), redirect.token.begin(), redirect.token.end());
    return {22, std::move(payload)};
}
GameAdmission richonline_expected_admission(RichonlineAdmissionIdentity identity,
                                            const RichonlineGameRedirect& redirect) {
    if (redirect.port == 0) throw CodecError("richonline_game_redirect_port_invalid");
    GameAdmission admission{identity.manager, identity.room, identity.player, redirect.token, redirect.extra, {}};
    return admission;
}
}
