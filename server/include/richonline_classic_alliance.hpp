#pragma once
#include "richonline_player_cards.hpp"
#include "lua_server.hpp"

namespace richnet {
// P+1472是有期限的同盟，不能与P+1480队伍标志混用。开局八槽全零。
using RichonlineClassicAlliances=std::array<std::array<std::uint8_t,8>,8>;
void break_richonline_classic_alliance(RichonlineClassicAlliances&,std::uint8_t source,std::uint8_t target) noexcept;
void clear_richonline_classic_alliances(RichonlineClassicAlliances&,std::uint8_t actor) noexcept;
class RichonlineClassicAlliancePlan final {
public:
    const Bytes& response() const noexcept {return response_;}
private:
    const RichonlinePlayerCards* cards_=nullptr;
    RichonlineChanceInventory inventory_before_{},inventory_after_{};
    RichonlineClassicAlliances before_{},after_{};
    std::vector<std::uint8_t> active_;
    Bytes response_;
    friend RichonlineClassicAlliancePlan prepare_richonline_classic_alliance(View,std::uint16_t,
        std::uint8_t,const RichonlinePlayerCards&,std::span<const std::uint8_t>,
        const RichonlineClassicAlliances&,const std::shared_ptr<LuaServer>&);
    friend bool commit_richonline_classic_alliance(RichonlinePlayerCards&,std::span<const std::uint8_t>,
        RichonlineClassicAlliances&,const RichonlineClassicAlliancePlan&) noexcept;
};
RichonlineClassicAlliancePlan prepare_richonline_classic_alliance(View,std::uint16_t calendar,
    std::uint8_t days,const RichonlinePlayerCards&,std::span<const std::uint8_t> active,
    const RichonlineClassicAlliances&,const std::shared_ptr<LuaServer>& script={});
bool commit_richonline_classic_alliance(RichonlinePlayerCards&,std::span<const std::uint8_t> active,
    RichonlineClassicAlliances&,const RichonlineClassicAlliancePlan&) noexcept;
}
