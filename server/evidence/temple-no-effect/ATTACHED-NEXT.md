# Opponent temple: attached actor follow-up

Read-only live IDA verification,2026-10-09,instance5c7b48b1123e.
Database input SHA256 is recorded in README.md. Opponent duration-only
transitions are now integrated when the turn owner has an NPC coordinator;
actual summons and unimplemented effects remain rejected.

## Confirmed NEW branch mapping

7C6640 lines938-1067:

| Jump entry | Implementation | Meaning |
| --- | --- | --- |
| 611B29 | 7D7000 | NPC == 2 |
| 60735E | 7D6FE0 | NPC == 1 |
| 5FF7FD | 694D10 | NPC == 6 |
| 60A35B | 7D7040 | NPC == 7 |
| 60B017 | 7D7020 | NPC == 3 |
| 60EFB9 | 7D6FC0 | NPC == 0 |
| 605923 | 694CF0 | NPC == 4 |
| 610AC1 | 7D70D0 | MI hai column0, enemy harmful days |
| 601ECC | 7D7100 | MI hai column1, enemy harmful effect |
| 6122E0 | 7D7130 | MI yi column0, enemy beneficial days |
| 60A5A9 | 7F7E30 | Add byte days, signed compare with maximum |
| 607E1C | 7FAE80 | Effect and multiplier update |
| 604E42 | 7D7430 | Subtract byte days |
| 60A1F3 | 7F7CF0 | Decrement once more, return NPC if days <= 0 |
| 60AFBD | 693570 | Construct local animation record6050 |

Enemy harmful NPC IDs1,2,6,7 extend only if hai days > 0; effect updates only
if hai effect > 0. Current resource levels1-3 have zero/zero, levels4-5
extend by1/2. The extension narrows to a byte before the signed maximum
comparison. Do not replace this with an unsigned saturation operation.

Enemy beneficial NPC IDs0,3,4 detach when yi days <= 0. For yi days > 0,
7D7430 subtracts configured days and7F7CF0 then decrements again before
testing expiry. Current levels1-3 therefore reduce by2/3/4 in ordinary
non-wrapping cases; levels4-5 detach. The6050 record is a client-local
animation record, not an additional server packet.

## Implementation and verification

The duration planner mirrors byte narrowing before signed comparisons.
RichonlineNpcSession prepares against status, clock and generation; its commit
updates both state and duration, preserving last_actor_turn. The turn owner
commits the property result before selecting a junction or advancing the turn.
The session binding supplies maximum days from NEW GValue item37. NEW7B9AD0
loads values into A87080[index]; A87114 is offset148, hence index37. Fresh live
evidence for this loader and duration operations is in
`attached-clock-evidence.json`.

The current resource levels1-5 support existing NPC0,1,2,3,7. Effect changes
outside this support remain gated. A property owner without the NPC coordinator
still rejects attached visits. Positive-only checks were removed from the
mirrored raw duration byte: NEW addition can wrap into128-255 or0, and the next
tick must preserve the signed-byte behavior (including128 ->127).

Validation:

- NPC spawn test checks reduction plus the extra tick, immediate detach,
  extension maximum, addition/subtraction wrap, and subsequent raw-byte expiry.
- NPC session tests exercise both actors, pending roulette rejection, stale and
  duplicate commits, same-turn identity, and unchanged money/inventory/ground.
- Property test checks actual MI duration fields for NPC0,1,2,3,7 at levels1-5.
- Encrypted TCP: both actors visit both actual map endpoints with no NPC and
  ground NPC0,1,3 (16 sessions total), including human roulette and fortune
  replies. After transport shutdown the authoritative clock is ticked to verify
  the duration actually committed by the turn owner.
- Full strict build and202/202 CTest pass,54.72s:
  `build/protocol-temple-attached-build.log`,
  `build/protocol-temple-attached-tests.log`.

## Remaining work

Own/friendly duration handling has since been added; see `OWN-TEMPLE.md`.
Actual summons and effect multiplier updates remain incomplete. Do not enable
gated maps until these and fixed endpoint/long session regressions are verified.

Existing original_god_state.cpp confirms analogous logic but must not be used
as sole NEW evidence. RichonlineNpcSession::prepare_status_change preserves
duration or detaches; prepare_temple_change now handles duration explicitly.
