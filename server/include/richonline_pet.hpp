#pragma once
#include "richonline_route.hpp"

namespace richnet {
// 逻辑跟随格与动画当前格是两份状态。旧客户端按动画格判定占用，不能直接套用此逻辑格。
// 原协议402E在主人停步后复位宠物；只有该边界或真实重定位后当前格才确知。
struct RichonlinePetState {
    bool equipped=false;
    std::int16_t follow_target=-1;
    std::optional<std::int16_t> known_display_position{};
};
std::int16_t richonline_pet_reset_position(const RichonlineRoadTopology&,std::int16_t owner,std::uint8_t heading);
void reset_richonline_pet(RichonlinePetState&,const RichonlineRoadTopology&,std::int16_t owner,std::uint8_t heading);
void follow_richonline_pet_step(RichonlinePetState&,std::int16_t previous_owner) noexcept;
Bytes richonline_pet_stop_sync(std::uint16_t game,std::uint8_t heading);
}
