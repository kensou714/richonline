#pragma once
#include "richonline_board.hpp"
#include "richonline_player_cards.hpp"
#include "richonline_raw_authority.hpp"
#include "lua_server.hpp"

namespace richnet {
// 按角色槽顺序保存共享会话权威值；未知收容字段不能当作可参与换位。
struct RichonlineClassicRelocationActor {
    std::int16_t position;
    std::uint8_t heading;
    bool active;
    RichonlineRawActorState raw;
    RichonlineActorStatus status;
    bool operator==(const RichonlineClassicRelocationActor&) const = default;
};
class RichonlineClassicRelocationPlan final {
public:
    const Bytes& response() const noexcept {return response_;}
private:
    const RichonlinePlayerCards* cards_=nullptr;
    RichonlineChanceInventory inventory_before_{},inventory_after_{};
    std::vector<RichonlineClassicRelocationActor> before_;
    std::vector<std::int16_t> positions_;
    Bytes response_;
    friend RichonlineClassicRelocationPlan prepare_richonline_classic_swap_positions(View,std::uint16_t,
        const RichonlinePlayerCards&,const RichonlineRoadTopology&,
        std::span<const RichonlineClassicRelocationActor>,const std::shared_ptr<LuaServer>&);
    friend bool matches_richonline_classic_relocation(const RichonlinePlayerCards&,
        std::span<const RichonlineClassicRelocationActor>,const RichonlineClassicRelocationPlan&) noexcept;
    friend bool commit_richonline_classic_relocation(RichonlinePlayerCards&,std::span<RichonlineBoardParticipant>,
        std::span<const RichonlineClassicRelocationActor>,const RichonlineClassicRelocationPlan&) noexcept;
};
RichonlineClassicRelocationPlan prepare_richonline_classic_swap_positions(View,std::uint16_t calendar,
    const RichonlinePlayerCards&,const RichonlineRoadTopology&,std::span<const RichonlineClassicRelocationActor>,
    const std::shared_ptr<LuaServer>& script={});
bool matches_richonline_classic_relocation(const RichonlinePlayerCards&,
    std::span<const RichonlineClassicRelocationActor>,const RichonlineClassicRelocationPlan&) noexcept;
// current须从同一共享会话即时读取；只写坐标和主手牌，保留角色自己的朝向和其他字段。
bool commit_richonline_classic_relocation(RichonlinePlayerCards&,std::span<RichonlineBoardParticipant>,
    std::span<const RichonlineClassicRelocationActor> current,const RichonlineClassicRelocationPlan&) noexcept;
}
