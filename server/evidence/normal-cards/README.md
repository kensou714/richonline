# Normal cards protocol repair - 2026-10-10

## Latest map-ready and card-dispatch increment

- Ready/start rejection in`data/logs/native-50540.jsonl:90/98/120` is
  `richonline_ground_card_range_policy_invalid`. The ground policy validator now
  accepts the GUI viewport policy. All 13 registered BOSS map packages are enabled;
  BS_2_* and BS_3_* currently use the shared simulator mechanics.
- [92-entry dispatch audit](card-dispatch-92.md) records every registered card,
  its response, passive/local-only boundary or explicit mode refusal. It is not
  a claim of all original gameplay effects or client acceptance.
- New stateful branches include jail entry/clock/exit, ten-step road clearing,
  alliance expiry, actor swap, detonation, teleport, status clearing and treaty.
  Visual cards and lottery also have responses. A synthetic BOSS has no hand,
  so theft is a logged400B refusal without consumption.
- Planning refusals recover action controls. Prepared inventory/ground/clock
  failures and errors after a commit are not mislabeled as normal refusals.
- Strict server compilation succeeded; no tests were added or run, and the
  service was not started. Installed SHA256:
  `52C3287A67F8AD1660F30A83A4A443C294E373C7A3459450E38C8861C61454EE`.
  Backup/manifest:`build-migration-backup/boss-map-card-dispatch-5702a9d4950a460bbd2ff78bf72148ad/installation.json`.

## Failure evidence

Source: `server/data/logs/native-13212.jsonl`.

| Card | C2S | Log lines | Disconnect reason |
| --- | --- | --- | --- |
| Tax 1051 | 114 | 267-269 | richonline_boss_action_out_of_phase |
| Mine 1044 | 109 | 343-345, 2804-2806 | richonline_combat_human_card_target_not_authorized |
| House 1062 | 123 | 1259-1261 | richonline_boss_action_out_of_phase |
| Roadblock 1043 | 108 | 1945-1947 | richonline_boss_action_out_of_phase |

Each request has an eight-byte plaintext body and is followed by terminal cleanup
with `game_connection_closed`. These are protocol refusal disconnects, rather
than a legitimate bankruptcy result. Three normal card dispatch branches were
missing. Human mine targeting incorrectly inherited the configured BOSS range
and a restricted landing pool.

## Client contract (IDA-MCP)

Database: `RnClient.exe`, instance `5c7b48b1123e`. Successful live IDAPython
decompilation was used to inspect the handlers and senders.

| Card | S2C | Dispatch thunk | Handler |
| --- | --- | --- | --- |
| Roadblock | 40BC | 7F0910 -> 6045CD | 66DF70 |
| Mine | 40BD | 7F0930 -> 609753 | 66E1E0 |
| Tax | 40C2 | 7F09D0 -> 6010B2 | 66FEE0 |
| House | 40CB | 7F0AF0 -> 5FFE42 | 672AE0 |

Successful packets are eight bytes: WORD opcode, WORD game ID, BYTE inventory
slot, BYTE inventory bank, WORD target. Tax uses a signed BYTE actor at offset6
and zero at offset7. The success handler consumes the card and resumes actions;
there is no additional acknowledgement.

- Tax transfers cash/10 and deposit/10 separately, with integer truncation;
  19 cash plus 19 deposit transfers 1 of each. Zero balances do not cause
  bankruptcy. Positive bilateral relations are cleared.
- Mine sender 654190 and roadblock sender 653FA0 do not use the server's BOSS
  Manhattan radius. Human mine placement now uses actual landing preflight;
  BOSS targeting retains its configured range. Occupied, portal and unsupported
  continuation targets remain refused.
- Roadblock is ground type11; mine is type12. Both record the card user as
  owner. Mine lifetime comes from the resource rules.
- House sender 655D60 checks owned/friendly land in mode3, scenario caps and
  actor building skills for existing buildings. Empty buildings use the default
  kind; existing kind is preserved and level increases once. Animation21 ->
  634DA0 -> 7E3F30 caps mode3/4 levels at7. Only card1062 is consumed; money and
  construction permits are not charged.
- Movement 7F5D90 stops and removes a roadblock. Predicate 60556D -> 7FDA70 is
  type11, 5FF875 -> 7ECA20 is type30, and 60F2B1 -> 7E28B0 clears the ground
  bytes to -1. Both ordinary and timed-bomb-enabled movement now consume
  roadblocks as well as banana peels on acknowledgement.

## Implementation and validation

Normal successful requests commit the inventory, ground, property or shared
ledger transaction and send the documented success response. Planning refusals
send the existing five-byte 400B dice recovery response and retain the action
phase and inventory. Refusal reasons are logged. Commit failures are not caught
and relabeled as ordinary refusals.

`richonline_owned_property_tcp_tests.cpp` exercises all four cards through the
real encrypted GameService TCP connection, asserts exact plaintext responses,
checks authority and card consumption, and rolls after success/refusal.
Dedicated flow tests exercise roadblock placement, stop, removal and the next
turn; timed-bomb movement also checks roadblock removal. Property tests cover
scenario building caps and rejection of stale prepared commits.

Focused validation: `build/normal-cards-focused.log`, 8/8 passed.
Earlier candidate full validation: `build/normal-cards-final-tests.log`, 205/205 passed.
These checks do not establish real game client UI acceptance.

## Roadblock stop and badluck half repair

- Runtime evidence: `data/logs/native-8544.jsonl`, lines674-686: successful108/40BC,
  then0010/4011, then0011 disconnects with `richonline_boss_endpoint_mismatch`.
- Live IDA: movement7F5D90 checks NPC11 via60556D -> 7FDA70 before route exhaustion
  and bank processing. The client removes the obstacle and immediately sends0011.
  The server now authenticates the route prefix through the first roadblock while
  retaining the complete4011 dice and direction coverage required by the client.
  Unvisited bank checkpoints and ground objects are excluded from the accepted route.
- Roadblock placement no longer inherits the BOSS Manhattan radius. Walkability,
  occupancy, inventory and other legality checks remain in force.
- Badluck4024 handler65F410 consumes one card per non-sentinel slot. The server
  previously sampled up to four units regardless of inventory size. It now samples
  floor(total card units / 2), bounded by the map limit and four wire entries, with
  unused entries set to -1. Two units therefore lose exactly one.
- Focused flow, encrypted TCP, badluck and NPC session checks passed before the
  user's workflow change. No full suite or GUI self-test was run for this candidate.
- Per the user's instruction, further development uses log/IDA analysis, code and
  compilation; gameplay testing is performed by the user.
- `cmake --build server/build --target RichOnline.Server` succeeded. Installed
  candidate SHA256: `B2D767A7A8A66A0A5F316590AAA3B4D3B4CA35D14DE38C17F06BB67B9A4A6DDC`.
  Installation manifest: `build-migration-backup/roadblock-half-candidate.json`.

## Demolition and monster cards

- No101/102 use was present in the inspected live server logs. Source inspection
  showed both requests falling through the missing-action branch. This increment
  closes those dispatch branches; it is not a claim of reproduced client failure.
- Live IDA-MCP on `RnClient.exe`, instance `5c7b48b1123e`: sender653200 and
  constructor692410 establish101/card1036, eight bytes with a normalized signed
  WORD property ID at+6. Handler66C8E0 establishes40B5 with the same target, and
  reduction of one level. Sender6533A0 and constructor692440 establish102/card1037,
  six bytes without a target. Handler66CB00 establishes six-byte40B6 and the
  current actor's road-to-property mapping (6066CF -> 63E3E0).
- Monster animation17 lowers five levels.7E4020 clears exhausted sprite12
  buildings to level0/kind-1 and preserves ownership. Selectors606D69 -> 692030
  and60F6E9 -> 63F290 exclude building kinds8/9/10 and empty buildings.
  Existing source evidence: `docs/逆向资料/专题/40B0系列事件`.
- Both cards prepare against the shared property snapshot and inventory, then
  commit through the existing serialized callback. Planning refusals return400B
  without consuming the card. No second building store or extra animation packet.
- Strict `RichOnline.Server` compilation succeeded. Per the user's instruction,
  no tests were added or run. Gameplay acceptance is pending user verification.
- Installed SHA256: `B1EDDA64AC9D57A1E47806A5FF85EF4D6126D4C86D820C6E23F7A47D455999FE`;
  manifest: `build-migration-backup/destruction-cards-candidate.json`.

## One-step and six-step cards

- Live log `data/logs/native-20428.jsonl`: lines304-306 (141) and1128-1130
  (136) show eight-byte requests followed by `richonline_boss_action_out_of_phase`
  and connection cleanup. Both target-card dispatch branches were missing.
- Live IDA: senders657680/657B30 and constructors692CA0/692D90 establish
  136/card1079 and141/card1084. Fields are counter WORD+2, inventory slot BYTE+4,
  bank BYTE+5, target actor BYTE+6 and unused BYTE+7.
- Handlers674BF0/6755F0 consume seven-byte40D8/40DD confirmations. Protected
  targets are immune; otherwise7F83B0 clears1498/1501/1502/1496. Other actors
  receive one/six-step duration from GValue[18] (A870C8); the current actor
  does not retain that status and does not restore controls through6006.
- The existing motion-card planner now handles both requests. Self use sends
  confirmation followed by authoritative4011 for one/six steps; another target
  receives the fixed-step status and local controls resume. Protected self use
  follows the existing400B recovery policy. Route preparation precedes card
  consumption and status commit.
- Strict `cmake --build server/build --target RichOnline.Server` succeeded.
  No tests were added or run. Candidate SHA256:
  `3E91AE20DAECF930DF0C0152327017C41FB0C02E073941DABC006EFBEC130F43`.
  Installed after user shutdown; gameplay verification is assigned to the user.

## Ground-card range correction

- Live log `data/logs/native-20428.jsonl:1419` shows ice1181 rejected with
  `richonline_research_trap_visibility`. Shared ground authorization still
  imposed the configured Manhattan radius on ice, banana and fire.
- Live IDA senders658ED0/653FA0/654190 select a map cell from screen coordinates.
  Helpers63E820 and63E880 check map bounds and road data; they do not impose
  the BOSS Manhattan radius. The request contains no camera rectangle.
- Shared human ground authorization now validates actor, source road and target
  map bounds. Existing card planners retain occupancy and static-cell rules;
  fire can use a non-road center. Legacy radius configuration remains readable.
  Human mine and roadblock already lacked the BOSS distance restriction;
  BOSS combat range and mine landing preflight remain in their existing owners.
- Both fixes compiled and were installed together. Backup:
  `build-migration-backup/one-six-ground-8057ce8611164b2d8a3ec1568dbab6d8`.
  No automated or GUI tests were run.
