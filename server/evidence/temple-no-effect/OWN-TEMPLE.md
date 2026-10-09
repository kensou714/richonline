# Own temple continuation

2026-10-09. This increment adds friendly/own kind16 effects to the existing
mode3 property and NPC clock coordinators. It does not enable gated maps.

## NEW evidence

Live IDA evidence is saved in `own-temple-evidence.json` and
`construction-phase6.json`, with database input SHA256 in each artifact.

- NEW7C6640 case8/LABEL35 offers an upgrade only below scenario and actor
  skill caps, then falls through LABEL52/case7 for existing-building effects.
- NEW661F50 (403D) resumes phase6 for first construction or cancellation;
  first construction must not immediately run temple effects.
- NEW662280 (403E) queues accepted level increment then phase2/subphase7;
  declined upgrade also resumes subphase7. Effects therefore use the new level
  after acceptance and the old level after cancellation.
- Controlled actors bypass construction/upgrade selection but still reach
  LABEL52. The previous server early return incorrectly skipped own temple.
- Friendly harmful days:60F450 ->7D7190, MI hai column2. Friendly beneficial
  days/effect:5FFC12 ->7D71C0 and6038B2 ->7D71F0, MI yi columns2/3.
- Friendly summon:60A716 ->7D7160, MI zao column1. Current level5 summons NPC4;
  this is still unsupported and explicitly gated.

## State and protocol contract

Existing NPC0/3 use friendly beneficial extension; NPC1/2/7 use friendly
harmful reduction/detach, with the established signed-byte duration rules.
The property module returns a duration transition, and the authoritative turn
owner commits it through the NPC session. A pending human temple upgrade saves
its landing context; accept, cancel and timeout return the corresponding effect
only after resolving that decision. No extra temple network packet is invented.

Validation checks both current and possible upgraded temple branches before
entering a decision. If either requires an unsupported summon/effect, the
landing remains rejected without mutating the building or opening a wait.
Thus a level4 unattached actor with an available level5 upgrade is still gated,
even though an isolated cancellation would be effect-free.

## Validation

- Property regression covers levels1-5 with NPC0/1/2/3/7, construction versus
  upgrade continuation, cap, controlled visits, accept/cancel/timeout, and
  rejection before unsupported summon/upgrade mutations.
- Encrypted TCP now covers37 fixed temple sessions:32 cases across two actual
  map endpoints, human/Boss, own/opponent, no NPC/NPC0/1/3; four human
  accept/cancel cases; one Boss automatic upgrade case. It verifies reply order
  and subsequent authoritative possession-clock expiry.
- Strict build:`build/protocol-own-temple-build.log`.
- Full regression:`build/protocol-own-temple-tests.log`,202/202 passed,60.73s.

Remaining: NPC4/6 temple summons and their effects, then deterministic and long
session map admission validation. No real client UI verification is claimed.
