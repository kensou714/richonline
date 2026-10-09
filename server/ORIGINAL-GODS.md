# Original god and NPC boundary

2026-10-09. C++20 implementation for the root RnClient.exe only. This is a library boundary, not a connected production match host. Keep the manager's `gameReady=false` until an actual original-client match passes acceptance.

## Evidence and resources

`protocol-analysis/ORIGINAL-GODS-RECHECK-20261009.md` records fresh original-client IDA evidence and binary identity. `original_god_resources` reads Npc.kpd, BwbValue.kpd and GValue.kpd directly through the native decoder. Raw GBK values and unknown fields remain available; absent affix/effect fields are not guessed as zero. The rules include all eight attachment durations, seven pyramid levels and the recovered five-day extension cap.

Attachment changes kind, source and signed-byte days only. Detachment clears a positive effect but preserves negative effects and the float multiplier. Tick and pyramid arithmetic reproduce byte narrowing before comparisons. A tick returns the expired kind so the owning match can apply the corresponding status cleanup; it does not invent a packet or advance a turn.

## Wire fields

| Message | Fields after opcode | Role |
|---|---|---|
| C2S34, six bytes | u16 action context, byte action=1, retained opaque byte | Current wealth selection |
| S2C4022, seven bytes | u16 Gmsv instance, i16 total amount, byte insolvency wait | Wealth result |
| S2C4023, eight bytes | u16 Gmsv instance, two i16 actual card IDs | New blessing reward |
| S2C4024, eight bytes | u16 Gmsv instance, four i8 main-bank slot indices | Misfortune removal |
| S2C401C, nine bytes | u16 Gmsv instance, i16 tile, byte object kind, two auxiliary bytes | NPC/chest spawn |

Ordinary NPC auxiliary FF/FF values are proved constructor defaults. This encoder accepts gods0..7, point-ticket chest9 and treasure32 only; mine owner/countdown fields require a separate encoder. A natural attachment already removes the map object locally; no duplicate removal401C is sent by these modules.

## Completion ownership

`OriginalGodEvent` retains landing/card/property origin and a distinct wealth/blessing/misfortune wait. Successful rewards release only the matching wait. Invalid or repeated results cannot grant twice. Finish reports the origin without sending4015 or4010. The owning match must resume the appropriate phase once and commit returned inventories/funds under its serialized state ownership.

Blessing inserts the two real card IDs sequentially, including synthesis after each insertion. A full inventory still receives a4023 with actual IDs; no fake zero reward is substituted. Misfortune removes one unit per selected slot, supports repeated slots, preserves slot tails and rejects over-removal atomically. Four-1 is the empty result. Neither result waits for an invented C2S acknowledgment.

Wealth god0 credits the actor the full amount and debits active enemies by integer share. God1 debits the actor and credits every other active player, including allies. Cash precedes deposit; insolvent balances clamp to zero. The result exposes affected slots and preserves a bankruptcy wait until the owning match explicitly completes it. A real bankruptcy protocol is still required before production integration. Amount distribution and card selection are explicit caller policy; their original server RNG is not recovered.

Pyramid effects use the actual final level, friendliness and player state. Level6 can wait for blessing/misfortune, level7 for wealth. The property owner calls `complete_pyramid(context)` only after the event finishes. Existing god effects and day changes are synchronous; no duplicate card or map-object response is added.

## NPC population policy

`OriginalNpcSpawner` implements the requested opening four distinct gods plus one point-ticket chest, minimum two and maximum five counted NPC/chest objects, and one new object per three context advances. The current uniform selection pool excludes land god5, matching its non-PK resource designation; this is a local server policy, not proof of the original server RNG. Kind32 counts toward the population; lottery-card33 occupies a tile but is not counted as an NPC/chest.

The owning match applies each returned spawn to its world before the next call, calls `refill` after removals, and supplies a monotonic full-width context rather than the truncated wire context. Duplicate context cannot generate an additional periodic spawn. Skipped intervals coalesce to one spawn. Occupied/object/property roads are excluded. Lack of space is reported explicitly instead of placing overlapping objects.

## Remaining production work

Natural god7 status/talisman handling, complete card-driven attachment dispatch, point-ticket/treasure/lottery rewards, full bankruptcy messages, expired-status cleanup, and original room-to-match integration still need implementation and real-client acceptance. Fresh evidence proves god7 consumes the object first, then either consumes an eligible1071 talisman and detaches or applies state6, continuing the underlying tile without another request. Angel/devil800 is a turn-prelude area effect, not immediate attachment damage; its damage/death continuation still needs integration. Current helpers do not establish a complete playable game. Lua strategy wiring, multiplayer authority and the remaining card/combat/settlement paths remain part of the overall migration.

The encrypted TCP scenarios use real GameService transport and native inventory/property/event modules. Startup, forced landings, settlement amounts, existing pyramid ownership and level7 cap are explicit fixtures. They verify boundaries and continuations, not original-client visuals or a full match.

Validation: final full native CTest74/74 passed18.47s. Eight new god/NPC/event suites include the two encrypted TCP suites. Build/test logs are `.omo/evidence/original-gods-{build,ctest}.log`. Actual .NET manager checks passed; rendered lifecycle/log/account/configuration evidence is in `.omo/evidence/native-manager-daa18b28188a4d948a4629893f8c483c`.
