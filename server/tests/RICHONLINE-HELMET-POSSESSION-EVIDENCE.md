# NEW1076 helmet and possession combat rules

Fresh read-only IDA-MCP evidence from Richonline/RnClient.exe, GUI lease
b9d986e39b81 (released after collection), is retained under
protocol-analysis/richonline-rebuild/game/combat-new/. Evidence files:
combat6_helmet_usage_lifecycle.json, combat6_helmet_usage_writes.json,
combat6_helmet_usage_helpers.json, combat6_Grant_startup.json,
combat6_possession_combat_terms.json and combat6_possession7_predicates.json.

## Automatic safety helmet

NEW7CDAB0 (thunk60ED70) is called by missile633B90, nuclear635610 and safe
nuclear636720 after each actor's eligibility/position check. It does not appear
in the mine or carried timed-bomb damage path. It checks the current game mode's
Prop1076 limit, finds the first matching bank0 hand slot via7F85C0, then checks
NEW800A50: valid Prop record, typeCARD and current-map membership via7E1080.
It does not read Prop.enable or the victim's sleepwalking state. Bank1 lookup
depends on a separate equipped-item predicate and unlock flag; the current
server authority supports bank0 only.

On activation it increments WORD game+5896+10000*actor, queues local effect4,
message267/sound316 and local6061 subtraction from that actual slot/bank, and
suppresses projectile damage. It does not require an additional network packet.
Coordinator preparation consequently consumes one1076, increases the shared
status.safety_helmet_uses WORD and emits only the original attack packet. These
changes commit together through the existing Bridge inventory/status/funds CAS.
The WORD increment deliberately retains NEW modulo65536 semantics.

NEW64F2A0 initializes8x5000 WORD per-game Prop counters by clearing10000 bytes
at game+3744+10000*actor. safety_helmet_uses=0 therefore reflects a proven startup
value, and no turn/day hook decrements it. NEW728150 increments and7281B0 reads
the same generic counter array; immediate searches found no other direct1076
counter writes in the inspected executable.

NEW7D9100 initializes all5x5000 Grant limits to-1. NEW7D91D0 parses repeated
PROP rows with prop, rule and literal num at A2D500. CM/PK/TC/BS/KO map to0..4;
later rows overwrite earlier limits. NEW7D98E0 returns-1 for modes outside0..4.
NEW623CB0 ignores the return of loading Data/Grant.kpd. That file is absent in
the supplied NEW resource tree, so constructor unlimited rules apply. A supplied
Grant file is parsed and enforced rather than replaced with hardcoded BOSS limits.

Real Prop1076 is typeCARD, enabled, shop-sale enabled, priceG100. BS_1_1 has a
1076 membership row with weight0: membership, rather than reward probability,
is the automatic-use gate. The default World factory reuses the independently
verified RichonlineChanceResources::automatic_card_eligible implementation.

Reusable API in richonline_combat_resources.hpp:

* RichonlinePropUseLimits::parse(grant), ::load(root), .limit(mode,prop),
  .allows(mode,prop,previous_uses).
* prepare_richonline_safety_helmet(inventory,previous_uses,mode,limits,eligible)
  is pure and returns the first-slot one-unit PreparedConsumption.
* World.helmet receives const actor/session snapshots, including the authoritative
  inventory and status.safety_helmet_uses; no mutable counter is captured.

## NPC possessions

Fresh NEW7CE420's four possession branches call exact actor+1488 predicates:

| ID | Predicate | Attacker multiplier | Defender multiplier |
| --- | --- | --- | --- |
| 0 | NEW694C90 | 1 | 0.5 |
| 1 | NEW694CC0 | 1 | 1.5 |
| 2 | NEW693D10 | 0.5 | 1 |
| 3 | NEW701530 | 1.5 | 1 |
| 7 | none of these equality predicates | 1 | 1 |

7CE420's remaining branches read active building sources1730/1734, duration
bytes1660/1661/1672/1673, equipment aggregate DWORDs1752/1760 and special byte1696.
They do not test possession7. Building-granted possession amplification is a
separate DWORD1740/float1744 pair checked by7016B0/7016E0 and written by7FAE80.
Its observed callers are property landing7C6640. Ordinary shared NPC attachment
does not grant that building amplification. It remains an explicit extension
for future building integration, rather than being inferred from possession ID.

richonline_unamplified_possession_combat_terms(actor,state) is exported as a
pure extra_terms provider for the current shared NPC0/1/2/3/7 model. The existing
damage calculator applies each base factor once and combines it with shared
attack/damage timers, active buildings and cash-dependent equipment. Unsupported
possession IDs still produce an explicit extension error.

## Verification and limits

Four standalone programs compiled with C++20 and
-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion, and passed:
richonline_combat_resources_tests.agent.exe, richonline_combat_session_tests.agent.exe,
richonline_combat_world_tests.agent.exe and richonline_combat_bridge_tests.agent.exe.

Checks include first-slot/one-unit consumption, map and zero-count gates, actual
weight0 membership, constructor defaults, mode-specific limit boundaries,
successive projectile quota exhaustion, protected sleepwalking victims, frozen
victim and safe-self exclusion, mines retaining helmets, WORD wrap, pure prepare,
stale Bridge rollback preserving inventory/counter/funds and successful atomic
commit. Every0/1/2/3/7 attacker and defender factor is tested separately, including
the combined3-attacker/0-defender750 damage result from base1000.

No live client test or full runtime deployment is claimed. Bank1 inventory,
building amplification and distinct secondary/special status owners remain outside
this closed shared model and require their own proven adapters.
