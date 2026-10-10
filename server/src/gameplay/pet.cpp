#include "richonline_pet.hpp"

namespace richnet {
std::int16_t richonline_pet_reset_position(const RichonlineRoadTopology& topology,std::int16_t owner,std::uint8_t heading) {
    if(heading>3) throw CodecError("richonline_pet_heading_invalid");
    const auto& cell=topology.cell(owner);
    // NEW7F7990：先做地图边界检查，再检查后方是否道路；否则与主人同格。
    const auto width=static_cast<std::int32_t>(topology.width());
    const auto height=static_cast<std::int32_t>(topology.height());
    auto x=cell.position%width,y=cell.position/width;
    switch((heading+2U)%4U) {
    case 0:++y;break;
    case 1:--x;break;
    case 2:--y;break;
    case 3:++x;break;
    }
    if(x<0 || y<0 || x>=width || y>=height) return owner;
    const auto behind=static_cast<std::int16_t>(y*width+x);
    return topology.cell(behind).walkable ? behind : owner;
}
void reset_richonline_pet(RichonlinePetState& pet,const RichonlineRoadTopology& topology,
    std::int16_t owner,std::uint8_t heading) {
    if(!pet.equipped) return;
    pet.follow_target=richonline_pet_reset_position(topology,owner,heading);
    pet.known_display_position=pet.follow_target;
}
void follow_richonline_pet_step(RichonlinePetState& pet,std::int16_t previous_owner) noexcept {
    if(!pet.equipped) return;
    pet.follow_target=previous_owner;
    // 移动确认只有主人落格；不能根据服务器墙钟猜测独立动画已追上。
    pet.known_display_position.reset();
}
Bytes richonline_pet_stop_sync(std::uint16_t game,std::uint8_t heading) {
    if(heading>3) throw CodecError("richonline_pet_heading_invalid");
    Bytes message;append_le(message,0x402e,2);append_le(message,game,2);message.push_back(heading);
    return message;
}
}
