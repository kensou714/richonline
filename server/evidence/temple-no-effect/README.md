# NEW opponent temple continuation

Verified on 2026-10-09. Source: the existing IDA GUI database for NEW RnClient.
Raw pseudocode and resource loader evidence: `ida-evidence.json`.

This document records the initial no-effect increment. Attached duration-only
support and the current verification are documented in `ATTACHED-NEXT.md`.

## Supported Contract

- Opponent property kind16, actual topology/property reference, mode3.
- Actor has no possession; MI `level_N_zao[0]` is -1.
- Current NEW BwbValue levels1-4 satisfy this condition. Level5 summons NPC6
  and remains rejected; levels6-7 exceed the current building level gate.
- C2S0011 completes with S2C4013, followed by the next actor's4010/420F
  and, for a Boss turn,4011. There is no temple decision or extra reply.
- Cash, ownership, building and possession remain unchanged.
- Attached actors and actual summons remain rejected. This change does not
  enable BS_1_3 or V_BS_1_1 in the production map catalog.

## Evidence

NEW7C6640 opponent branch calls61261E ->7D70A0 for an unattached actor.
7D70A0 reads the enemy summon field populated by7AF4A0 from MI zao column0.
The -1 branch returns true without an effect record or wait. Existing NEW
resource evidence is at
`F:/大富翁online/protocol-analysis/richonline-rebuild/game/startup-flow/resource-init/BwbValue.decoded.txt`.

IDA database input SHA256:
`CB35F69F3D49C2093897D4EA2CB547A1E38B213F3A8DF0AF52B859F9E661DE77`.
Workspace RnClient.exe SHA256:
`A23410E79637E312C932F861176D8D81CD1FD5D222A286F279FECCDECE6263C2`.
The workspace executable is the patched compatible derivative; its disk hash
must not be represented as the database input hash.

## Regression

- Opponent property test: resource levels1-4; level5 rejection; attached
  supported NPC rejection; actual BS_1_3 road164/property149 and V_BS_1_1
  road165/property198.
- Owned property TCP test: actual encrypted GameService sessions for both
  human and Boss visitors on each of those map endpoints.
- NPC session and collision/bank tests: projected attachment preflight rejects
  before shared ground, inventory, ledger, status, clock or wait changes;
  turn-owner retry remains possible.
- Strict build: `build/protocol-temple-build.log`.
- Full CTest: `build/protocol-temple-tests.log`, 202/202 passed,64.03 seconds.

No actual client UI or live database was changed by these tests.
