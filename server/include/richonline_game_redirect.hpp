#pragma once

// 新版游戏跳转：保存目标地址与 8 字节令牌，生成预期准入描述。

#include "game_admission.hpp"

namespace richnet {
struct RichonlineGameRedirect {
    std::array<std::uint8_t, 4> address;
    std::uint16_t port;
    std::uint32_t extra;
    std::array<std::uint8_t, 8> token;
};
struct RichonlineAdmissionIdentity {
    std::uint32_t manager;
    std::uint32_t room;
    std::uint32_t player;
};

Frame encode_richonline_game_redirect(const RichonlineGameRedirect& redirect);
GameAdmission richonline_expected_admission(RichonlineAdmissionIdentity identity,
                                            const RichonlineGameRedirect& redirect);
}
