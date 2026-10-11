#pragma once
#include "richonline_special_landings.hpp"
#include "control.hpp"

namespace richnet {
// Session-owned mode3 merchant57 bridge; the caller serializes all actions.
// Map package playability is checked by make_richonline_boss_session, not here.
class RichonlineMerchantSession final {
public:
    // NEW7D5E10 tests raw signed game+83830 != -1, including raw0.
    // nullopt means the owner has no synchronized authority for this field.
    using ScriptedStateReader=std::function<std::optional<std::int8_t>(const RichonlineLandingContext&)>;
    RichonlineMerchantSession(RichonlineRoadTopology,std::shared_ptr<RichonlineGameLedger>,
        std::uint16_t game,std::uint16_t room,std::string package,ControlLog,ScriptedStateReader);
    bool validate_landing(const RichonlineLandingContext&) const;
    std::optional<RichonlineLandingResult> land(const RichonlineLandingContext&);
    // Lua落点先准备，再验证完整回包，最后调用commit；准备阶段不改账本。
    std::optional<RichonlinePreparedSpecialLanding> prepare(const RichonlineLandingContext&,std::int8_t&) const;
    RichonlineLandingResult commit(const RichonlineLandingContext&,RichonlinePreparedSpecialLanding&,std::int8_t);
private:
    RichonlineRoadTopology topology_;
    std::shared_ptr<RichonlineGameLedger> ledger_;
    std::uint16_t game_,room_;
    std::string package_;
    ControlLog log_;
    ScriptedStateReader read_scripted_state_;
};
}
