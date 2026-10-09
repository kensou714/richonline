# Temple NPC4/6 and turn aura

2026-10-09. Applies to the current two-actor mode3 server only.

## Evidence and corrected field meaning

`npc46-aura-evidence.json` retains NEW7CEA20, its local consumers, funds accessors and x87 instructions. `npc46-strength-field.json` retains the constructor, setters, predicates and detach path against input SHA256 cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77.

- NEW7C6640 summons NPC4 from friendly level5 temples and NPC6 from enemy level5 temples. Local6051 has actor+2, god+3, origin+4=2 and groundWORD+6=-1. It returns completed; no new network reply or roulette request is needed.
- NEW67F8F0 consumes6051, then7F7DB0 sets1488/1489/1490 from the god resource. Ground is removed only when its position is not -1.
- NEW7C0C50 runs possession expiry before7CEA20. GValue15=800 and24=2 define the base amount and coordinate-square radius. Boss is excluded as a target, including when Boss is the source. Hospital1494, jail1495 and kidnapped1497 must each be -1; hotel1493 and movement552 are not filters.
- Local6060 adds cash. Local606E consumes cash then deposit;6803C0 checks605545 ->63F620, which returns cash alone. Cash0 is bankrupt even when deposit survives. This is not the usual total-funds depletion rule.
- Field1740 is a strengthening value, NOT a duration.7FAE80 writes its integer input to1740 and derives1744 (NPC4/6: (value+100)/100).7F3840 initializes1740=0;7F7D50 detaches and clears positive1740 via7FDBA0.7E51A0 is research queue advancement, not an aura timer.
- x87 stores the integer base as float, multiplies float operands without storing the product to float, then truncates to integer. The planner uses a double product to preserve that result.

## Implementation boundary

`RichonlineNpcSessionPolicy::temple_aura_affix` is temple-only. It does not add4/6 to ground spawning or deity-card selection, whose other behaviors remain unclosed. The prepared attachment preserves own-turn identity and checks generation, expected status and pending transactions. Existing duration extension/reduction also works for these gods.

Production sessions enable temple summons only with an NPC coordinator, terminal handler, shared ledger and actual raw-actor authority. The aura executes after expiry, commits every affected balance through the ledger batch transaction, and routes bankruptcy through the existing terminal owner.4010 triggers the matching client-local effect; the server sends no invented6060/606E packet.

Current level1-5 resource strengthening fields are zero. Property still rejects positive strengthening effects before any upgrade mutation; therefore every admitted source has constructor1740=0. The turn owner does not substitute combat attack/damage multipliers. The standalone planner covers known positive multipliers, but production does not enable their setters yet.

## Validation and remaining work

- Planner tests cover square/nonroad boundaries, ordering, excluded actors, unknown raw state, cash/deposit and cash-only bankruptcy, float rounding, invalid inputs, atomic ledger rejection/exception and stale-snapshot rollback.
- NPC tests cover summon capability, ground dispatch remaining closed, attachment generation/replay, duration extension and expiry.
- Turn tests cover both gods, both sources, expiry-before-aura, Boss exclusion, cash0 with surviving deposit, terminal order and missing capability rejection.
-47 fixed temple encrypted TCP scenarios: the prior37 plus10 new cases across BS_1_3 and V_BS_1_1, human/Boss, friendly/enemy summons, level4 upgrade acceptance/cancellation and retired upgrade replay. They verify funds and authoritative own-turn expiry.
- Strict build and full regression: `build/protocol-npc-aura-final-build.log`, `build/protocol-npc-aura-final-tests.log`.
- The existing long-session driver assumed selected dice always override fixed-step chance status. A retained random run disproved that assertion (BS_1_4, session1, calendar6; `build/protocol-npc-aura-dice-fixture-failure.log`). The driver now tracks category7/8/9 from received4096 and the previous-actor clock, requiring one die and zero charge while that effect remains. It still verifies the SQLite debit against the expected wire charge.

BS_1_3 and V_BS_1_1 remain production gated until dedicated long-session admission validation completes. No actual client UI acceptance or deployment is claimed. Research1181-1183 and lobby39/40 integration remain subsequent work.
