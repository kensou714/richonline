# Original BOSS match coordinator

2026-10-09. C++20 integration boundary; the original-client playable migration remains incomplete and `gameReady` stays false.

`OriginalBossMatch` owns one human (slot0), one BOSS (slot1), a full-width context, both movement states, inventories/funds, the property directory, research queue and active shop. `original_boss_match_plan` supplies real `OriginalGamePlan` callbacks for the existing admission/session/host boundary. This is not a production provider in `control.cpp`: unsupported attack configuration is rejected before admission instead of silently disabling the user's four-attempt attack policy.

## Connected behavior

- Startup copies each participant's first four inventory slots through4019, without synthesis. Human initial cards come from stage settings; more than four initial records are rejected. Remaining slots retain the proven constructor state. BOSS inventory is empty under the user's intrinsic-attack rule.
- Normal4010 uses current slot and round origin1. Full context increments once per turn; C2S uses low16 and S2C uses the distinct instance.420F(-1) resumes the prelude. BOSS movement starts server-side; a human connection reports its17. BOSS never waits for52.
- Human dice, movement endpoint, card-slot discard50, direction52 and independently pending property/shop requests route to the existing typed handlers.53 is a four-byte shop refresh request, not discard.
- Human shop opening, purchase, sale, discard, manual exit and idle10-second expiry share one wallet and close continuation. Close resumes property evaluation when applicable, then a human fork, then the next turn. The last closed context tolerates only its exact late48/-1. Opening a new shop clears that tombstone, including context wrap reuse.
- BOSS shop entry emits4030 then4031(-1) before switching actors. It cannot leave a pending shop or human direction dialog.
- Static5/6/7 mirror human ticket increments80/50/30 without duplicate result packets. BOSS skips tickets and8/41/42 cards. Human8 uses an explicitly local weighted-table draw;41→1044 and42→1046 are recovered from originalHelp/Prop resources.4029 applies real inventory/synthesis and precedes continuation.
- Actual EMP-linked properties support purchase, free default research-center construction, upgrade and research scheduling. BOSS buys/builds/upgrades using explicit local choices; human choices retain the turn. Completed research is mirrored on the recipient's turn without duplicate4029.

Wire suffixes, route storage and unused AI choice bytes remain explicit caller inputs. No opaque byte is described as a recovered business field merely because an encoder accepts it. Refer to `protocol-analysis/ORIGINAL-TURN-WIRE-20261009.md` and `ORIGINAL-BOSS-RUNTIME-RECHECK-20261009.md` for saved original-client evidence.

## Still unavailable

This coordinator is deliberately not enabled in the launcher. It does not yet own intrinsic BOSS attacks, dynamic gods/NPCs, card activation, movement-interrupt combat, bankruptcy/settlement, multiplayer authority/loading barriers, Lua strategy configuration or durable account refresh debits. The existing lower-level modules are not equivalent to their integration here.

The first map contains types68/69/70 that suspend the client for special outcomes. They report an explicit error with tile/type/context; they are never silently treated as ordinary roads. Same-tile encounters, pyramids, positive-level buildings other than research centers, and construction of other building kinds similarly remain explicit unsupported branches. Consequently an unrestricted first-stage playthrough is not ready. The configured attack policy requires four attempts; constructing this coordinator with any nonzero attempt count currently fails `original_boss_attack_strategy_unavailable`. Tests disable attempts explicitly to exercise this integration boundary, not to change production defaults.

The effective shop refresh price remains unproved: the root GValue file lacks index260. A refresh therefore uses the existing bounded4031(-1) rejection with its reason, preserves wallet state, and resumes the actual fork/turn. No free refresh or fabricated paid balance is emitted.

## Verification

Three new suites cover independent4010/420F/4019 bytes, real first-map match scheduling and actual encrypted GameService TCP. The TCP scenarios cover manual and idle shop close, no extra turn during decisions, low16 rollover, a late old shop exit followed by a valid new-context BOSS report, client attempts to roll for BOSS, and explicit unsupported70 failure. Direct scenarios include BOSS shop auto-close, human purchase/build waits, BOSS automatic purchase, card reward, discard and unsupported refresh.

The first TCP run failed at real tile121/type70; the main scheduling narrative now uses independently verified card tiles124/125 while a separate case preserves exact rejection coverage for121. Another direct run exposed reversed50/53 dispatch and its test input; the final dispatcher matches the existing proven parser and separate tests cover both shapes. No original-client UI playthrough is claimed by these transport results.
