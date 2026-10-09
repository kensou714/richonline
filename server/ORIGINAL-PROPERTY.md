# Original property and research boundary

2026-10-09. C++20 original-client migration, using root RnClient.exe evidence only. This module is a library, not the production BOSS match host. The manager must retain gameReady=false until original-client gameplay acceptance.

## Resource ownership

`original_building_resources` reads original Data/BossWar.kpd and Data/BwbValue.kpd directly through the existing native KPD decoder. Full decoded bytes, unknown fields and GBK values are retained. All eight MAP records and seven YAN choices are tested against the actual resources. `require(map_name)` requires the map and default kind, while each building cap remains optional. `OriginalBossProperties` rejects an unrecovered cap only when that kind requires it; omission is never silently converted to zero. Chapter-one known caps are5, chapter-two known caps6, while BOSS skill/hard bounds are7.

## Decision lifetime

The match supplies an authoritative actor, turn context, board slot, actual tile and eligible-friendly-owner predicate. It must apply the common game suppression guard before calling `begin`. Property identity is resolved from that tile, including multiple road tiles sharing a property; clients cannot select a property in their request. Actor skills come from startup or trusted AI policy. Calls are serialized by the owning match.

`begin` returns purchase/build/upgrade/research/pyramid/complete. Cash must be strictly greater than the discounted admission price; deposit does not bypass that UI condition. Kind10 shares the discounted admission gate but its4020 settlement charges the full base price. That charge uses cash then deposit, clamps insufficient funds to zero and does not introduce a bankruptcy wait: the original4020 consumer ignores the debit helper's insolvency return. Purchase changes owner only, preserving prebuilt kind/level, and completes that visit. Building is a later visit. Default kind needs no license, other enabled kinds consume one matching bank0 license stack unit, retaining all slot tails. Build and BOSS upgrade do not debit money. Build completes immediately; either accepting or declining upgrade runs building aftereffects.

Map cap reached, skill insufficiency or a controlling state never creates a fake pending33/56. They continue into aftereffects. Research requires non-AI and no confused god/sleepwalk/hibernation. Opponent research land does not open research; an explicitly eligible ally can research, with one job rather than the owner's three. Pyramid returns a pending effect even when a controlling state prevented upgrade. The match may call `complete_pyramid(context)` only after applying the actual god effect. No next-turn packet is fabricated inside this library.

`handle` preserves state on rejected decisions. It validates pending context and stage before mutation. Requests32/33/55/56/57 retain unassigned tail bytes and distinguish context from instance; replies use the observed five-byte read extent. Classic33/4021 has typed wire support only and is rejected by the BOSS decision handler. Human purchase argument+4=0 is proved by UI senders, not filler. Unknown purchase arguments are rejected.

## Research inventory synchronization

`OriginalResearchQueue` holds64 slots. Owner scheduling inserts d/2d/3d into first free slots; limited capacity accepts a partial batch, matching the client's independent insertion calls. Non-owner gets one. Every turn invalidates changed building kinds or insufficient levels; owner transfer alone does not cancel. Positive days decrement only on the recipient's turn, existing zero-day entries expire regardless of current actor, and negative signed-byte timers stay pending. Day multiplication follows byte narrowing in client storage.

Due jobs resolve in ascending slot order through shared inventory insertion and synthesis. Full inventory drops the output and clears the job. `advance` returns inventory changes and completion metadata, not a4029 packet: the original client already generates this reward locally. The owning match must apply the returned inventories at the same turn-prelude phase. Native tests cover atomic failure, order-dependent insertion, synthesis, partial capacity and ownership changes.

## Unfinished integration

- Room readiness and original production match host are not connected to these decisions yet. TCP scenarios use explicit fixture scheduling for repeated landings/day advancement; they do not demonstrate a playable full match.
- Only bank0 building licenses are supported. Persistent bank1 gates and debit semantics remain separate work.
- Eligible-friendly-owner and the common game suppression predicate need complete authoritative mapping before production use.
- Build-specific periodic initializers and missile-base/wall/totem turn effects remain unimplemented. Pyramid god effects now have a native event boundary and actual encrypted TCP tests, described in `ORIGINAL-GODS.md`; production host integration remains unfinished.
- Missing BossWar constructor defaults remain unknown. No absent cap is represented as a recovered zero.

Evidence: `protocol-analysis/ORIGINAL-PROPERTY-RECHECK-20261009.md` and the subsequent fresh `ORIGINAL-GODS-RECHECK-20261009.md`. The original property pass used saved raw evidence because C: was full. The later god pass recovered IDA operation, verified original binary identity, resolved kind10 and distinguished UI admission from settlement.

Validation: five property/resource/research suites, including actual encrypted GameService TCP purchase→later build→declined upgrade→research→silent inventory grant→sell/discard, plus license and skill-cap paths. Full native suite62/62 passed17.60s. Manager integration artifact: `.omo/evidence/native-manager-32a193d476f143269b1accd8e756cbee`. These are transport and management acceptance, not original-client gameplay acceptance.
