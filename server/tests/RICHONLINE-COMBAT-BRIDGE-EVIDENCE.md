# NEW shared combat integration adapters

Sources: `include/richonline_combat_bridge.hpp`, `src/gameplay/combat_bridge.cpp`,
`include/richonline_combat_resources.hpp`, `src/resources/combat_modifiers.cpp`,
shared property/ground additions. No second money/card/property/status authority.

Fresh NEW IDA evidence is under `protocol-analysis/richonline-rebuild/game/combat-new/`:
`combat3_property_*`, `combat3_equipment_*`, `combat3_resource_*`, and
`combat4_ground_fields.json`. Read-only GUI lease `ebb77b794a13` was released.

## Resource semantics

NEW 7AF4A0 reads BwbValue CHANG/ZHONG third CSV value. Active CHANG defense is
`(100-percent)/100`, active ZHONG attack `(100+percent)/100`, level1..7. Merely
owning a building does not activate its timed buff. NEW 7FF240 loads Prop.kpd:
att_desc gates equipment attributes. NEW 7F3C70 scans 32 encoded equipment words
at actor+144, low12bits are Prop ID. NEW 7FAF80 sums attackV/attackR/defendV/defendR,
with strict `<`/`>` current-cash conditions; absent fields and sparse default Prop
records are constructor-zero neutral. Parsing includes AVATAR, not only CARD.

Actor combat views have separate attack and defense modifiers. resolve_terms is
called before each attack/chain so cash-dependent attributes are re-evaluated.
It must also resolve possession and other enabled effects from real shared state.

## Property and ground

The property adapter exposes existing `properties_` as combat views. Ordinary
type12 footprint is lower-right anchor plus anchor-width-1, anchor-width,
anchor-1 (7E4440/635610). NEW 7E4020 type12 level1→0 resets kind=-1, preserving
owner. Type11's separate zero-kind0 rule is not substituted. CAS forbids increases,
ownership transfers, footprint changes, stale snapshots and pending decisions.
validate_landing is a pure version of the existing dispatch support check.

NEW 7CDE10/7CE120/7CE3A0 clear building production associations and actor active
building sources on downgrade/removal. Coordinator clears borrowed source refs;
production timers are not implemented in the property module yet, so this is not
a claim that production gameplay is complete.

NEW 66E1E0 creates type12 with current actor owner and A870CC lifetime; 7E2380
writes owner to dynamic+1 and lifetime+2. 694F70 decrements +2. Ground adapter uses
NPC12/byte7owner/byte8days. Type27 is supermine, not the red sprite; red is the
normal type12 lifetime<=1 rendering. Bridge rejects supermine until its separate
damage model is integrated.

Ground prepare allocates/validates before ledger callback, then matches and
commit_prepared provide no-throw one-use swap. Bridge prevalidates property,
ground, every ledger actor, cards and borrowed status/source refs, then applies
scalar/swap changes within ledger.commit_batch under serialized room execution.
No additional cash delta is emitted for damage the client computes locally.

## Turn integration boundary

Bridge constructor requires explicit World callbacks and per-map BOSS policy.
Methods accept short-lived borrowed ActorRefs; capabilities are explicit because
current Turns lacks authoritative hospital/prison/vehicle/building stores.
No hospital or immunity defaults are inferred. Return bankrupt_actors to the
terminal coordinator before continuing a turn; an absent active pointer is not
an authority for retaining eliminated actors.

Send actor4010 before BOSS attack packets, because 40BD owner and 40BF use
presentation take the current actor. Finish-round401E must run at round-anchor
after actor4010, before roll420F. Each complete day calls finish_round exactly
once (duplicate same identity is idempotent even with no mines). Scheduled
expiry sends one4017 per surviving connected root; stepped_mine sends no4017
because normal4013/608F already explodes and continues phase1.

Runtime construction and Turns hooks are owned by root/turn integration. These
tests do not establish real-client playback or enable unresolved map policies.

## Validation

Strict C++20 compile with Wall/Wextra/Wpedantic/Werror/Wconversion/Wsign-conversion:

- combat_session standalone: four draws, status gates, blast victims, chain
  ownership, atomic callback, separate modifiers, cash refresh, active source clear.
- boss_construction standalone: purchases/build/upgrades/timeouts plus combat
  CAS/replay/stale decision checks, zero-level rebuild, ownership removal, footprint.
- combat_resources standalone with real Richonline: real equipment234/235 conditional
  stats, real Bwb levels, BOSS1-1 neutral equipment, synthetic gate/mask/conditions.
- combat_bridge standalone with real Richonline: shared mine owner/countdown/red/
  expiry/stepping ledger, property downgrade, stale preparation no partial combat
  mutation, bankruptcy forwarding, prepared-ground one-use/stale validation.

All four passed independently using existing static archives without starting a
shared build or live process. Root adds CMake and performs integrated tests.

## World factory follow-up

`include/richonline_combat_world.hpp` and `src/gameplay/combat_world.cpp` construct
the shared World from actual Prop/Npc/GValue/BwbValue, selected BossWar stage and
verified road topology. `tests/richonline_combat_world_tests.cpp` passed a strict
standalone build/run against NEW resources. Actual supermine hurt is15000 (earlier
synthetic planner fixtures use5000 only to test propagation); supermine is still
rejected by the normal-mine bridge.

Factory input human_equipment is the actual32 profile words, not derived from
BoardInit (which does not retain them). Closed initial status mode admits empty
human equipment or an independently verified neutral permit whitelist. The
factory checks the whitelist has no combat attributes and rejects unsupported
equipment rather than fabricating immunity/secondary effects. BOSS equipment is
loaded from the selected stage; ordinary avatar combat terms are aggregated at
current ledger cash. Non-avatar capability slots require extensions. Extra terms
and capabilities retain extension callbacks. The default helmet resolver now uses
verified NEW Grant limits, CARD/map membership and the shared per-game use count;
see RICHONLINE-HELMET-POSSESSION-EVIDENCE.md.
Status attack/damage multipliers and implemented NPC0..3/7 possession effects pass
through the existing shared coordinator; no additional status copy is stored.

Range policy is explicitly `server_manhattan_tile_radius`, a configured tile
radius1..64. Projectile candidates may be actual road tiles or all map tiles;
mine candidates are actual roads passing the pure mine_landing_supported callback.
Own position is included when supported. This authorization policy is not the
client camera rectangle, which is not sent. The partial mine continuation boundary
must remain visible in runtime diagnostics; filtering unsupported targets does
not establish every movement-intermediate mine scenario.

World step uses the native topology neighbor order+width,-1,-width,+1. Active
Chang(kind13)/Zhong(kind14) sources validate property/owner/level then read actual
Bwb multipliers. The resources and equipment/active-building callbacks are pure;
shared property mutation remains in the bridge transaction. Actor active input is
borrowed from Turns, including the closed initial capabilities provider.

Root integrates factory source into boss_startup and its test into CMake, while
session/runtime own profile/range policy and bank_turn_integration owns Turns hooks.
Bridge additionally has pure has_mine(position) querying shared ground for the
landing owner; it does not add a private mine index.

## Human109/111 target cards

prepare_richonline_combat_human_card is a direct player plan, not synthetic BOSS
rolls. Bridge.human_card accepts the existing typed RichonlineTargetCardRequest
and authoritative expected calendar. Existing card parser enforces C2S109 exact8
and111 exact10 including constructor bytes8=0,9=1; semantic preparation checks
calendar, human actor/status, bank0/slot0..7, exact owned1044/1046, one-card
consumption and explicit World.card_targets. Ground occupancy is checked before
placing a mine. Normal40BD/40BF echoes actual slot/bank/target; missile BYTE8 is
authoritative actor0 and BYTE9=0 enables use presentation/hand consumption.

World.card_targets is separate from BOSS targets. NEW Prop1046 authorizes whole
map missile targeting; player mines use the explicitly named server tile-range
and partial mine continuation capability filter, without claiming a camera field.
Card preparation performs no writes. Bridge atomically commits inventory together
with mine placement or projectile damage/property/chain effects. No cash delta or
additional chain4017 is emitted. Terminal bankruptcy remains the caller's next
step; ordinary successful use restores controls through the existing client
handler and does not automatically roll or advance the turn.

Strict session/bridge/world standalone builds and executions passed with human
tests: exact packets, one consumption, stale calendar/bank/target/status rejection,
occupied-mine rejection, missile-plus-mine chain damage once, and real World
whole-map human missile versus bounded BOSS range. Session standalone now links
the existing cards wire encoder archive in addition to its former pure sources.
This is the109/111 closure only; bank1/2 inventories and other targeted cards are
not claimed by this addition.

## Nuclear124/133 continuation

The same direct human planner now handles C2S124 Prop1063 and C2S133 Prop1075,
with NEW exact10/calendar/slot/bank/target/constructor bytes0,1. Responses40CC and
40D5 retain actual inventory coordinates and authoritative actor with use flag0.
Fresh nuclear evidence in NUCLEAR-AND-MODIFIERS.md covers shared damage and
building effects, so this does not infer effects merely from packet symmetry.
World human targets follow the verified whole-map resource permission. Typed
parser, card manager, planner and bridge all map the four known kinds explicitly.
Tests passed for exact nuclear/safe packets, constructor/length rejection, one
consumption, normal nuclear self damage and shared property downgrade, and safe
nuclear self exclusion while the opponent is damaged.110 timed-bomb attachment
has a separate actor-target wire and is not part of this tile-target path.
