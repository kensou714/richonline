#pragma once

#include "richonline_boss_cards.hpp"
#include "richonline_map_package.hpp"
#include "richonline_game_bank.hpp"
#include "richonline_game_payment.hpp"
#include "richonline_npc_session.hpp"
#include "richonline_terminal_coordinator.hpp"
#include "richonline_result_delivery.hpp"
#include "richonline_combat_world.hpp"
#include "control.hpp"

namespace richnet {
struct RichonlineBossSessionPolicy {
    std::uint8_t opaque_turn7;
    std::array<std::int8_t,2> inactive_ui_dice;
    RichonlineRouteWirePolicy route_wire;
    RichonlineRouteChooser random;
    std::optional<RichonlineBossCardPolicy> cards;
    std::optional<RichonlineGameBankWirePolicy> bank = {};
    struct AccountPayment {
        double account_gold;
        std::string operation_prefix;
        RichonlineGamePayment::Debit debit;
        RichonlinePaidDiceEquipment equipment;
    };
    std::optional<AccountPayment> payment = {};
    std::optional<RichonlineNpcSessionPolicy> npcs = {};
    std::shared_ptr<RichonlineTerminalCoordinator> terminal = {};
    std::optional<RichonlineResultDisplayPolicy> result_display = {};
    std::optional<RichonlineCombatWorldPolicy> combat = {};
    std::optional<RichonlineMapLoadPolicy> map_loading = {};
    std::shared_ptr<const RichonlineTimedBombTurnPolicy> timed_bombs = {};
    // Required on maps with static 28/58/61 or merchant57. Read the room's signed
    // game+83830 value: -1 is normal; 0, 1 and 2 bypass those static effects.
    std::function<std::int32_t()> portal_scripted_state = {};
    std::function<bool(std::uint8_t,std::int16_t,std::int16_t)> ground_card_visible = {};
    std::function<RichonlineRawActorState(std::uint8_t)> hibernate_raw_actor = {};
    std::shared_ptr<RichonlineRawAuthority> raw_authority = {};
    LuaNative script_database = {};
    std::function<Bytes()> claim_boss_chest = {};
};

// Shared gameplay assembly. Map packages supply resources and policy; they do
// not parse socket frames, manage accounts, or duplicate the turn state machine.
RichonlineStartupPlan make_richonline_boss_session(const std::filesystem::path& resources,
    const RichonlineBossStartup& startup,const RichonlineMapPackage& package,
    const RichonlineBossSessionPolicy& policy,
    std::shared_ptr<const RichonlineChanceResources> chance,ControlLog log);
}
