# Normal cards protocol repair - 2026-10-10

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
Full validation and installed candidate hashes are recorded below after completion.
These checks do not establish real game client UI acceptance.
