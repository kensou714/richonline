# Owned Property Protocol Verification

Verified on 2026-10-10 against the existing implementation in
`src/gameplay/construction.cpp`, `property.cpp`, and `boss_turns.cpp`.
This verification continues the earlier fix; no new gameplay implementation
was required in this pass.

## Client Contract

Read-only IDA-MCP analysis of `RnClient.exe`, instance `4c30f33d33a1`:

- `0x661F50`: reply `403D` checks the game ID at +2 and accepts signed
  building choices 11..20 at +4, queues local event 6073, clears the wait,
  and resumes phase 6. A default request of -1 must be resolved by the server.
- `0x662280`: reply `403E` upgrades only when +4 is 1, queues local event
  6070, then clears the wait and resumes phase 2/subphase 7 on either answer.
- `0x6821D0` / `0x682230`: local events 6092/6093 open UI 41/5 for the
  local actor and establish pending states 23/24. They are not network packets.
- Construction and upgrade requests `0037` / `0038` are 6 bytes; replies
  `403D` / `403E` are 5 bytes. Research continues via `0039` / `403F`.

The owned-property implementation sends `4013` for the landing. BOSS actors
automatically build or upgrade within scenario and actor skill limits. Human
actors wait for `0037` or `0038` before the corresponding reply and turn
continuation. Research buildings retain their subsequent research decision.

## Runtime Evidence

Local server log: `data/logs/native-29592.jsonl` (timestamps in UTC).

- `2026-10-10T00:07:46.850Z`: player-owned property 104, empty building,
  pending opcode 55 (`0037`), followed by the player's construction request.
- `2026-10-10T00:08:01.575Z`: property 104, kind 11, level 1, pending
  opcode 56 (`0038`). Request at `00:08:02.599Z` is answered with `403E`;
  the subsequent research request at `00:08:05.591Z` receives `403F` and
  play continues to the next turn.
- `2026-10-10T00:09:54.309Z` and `00:10:17.883Z`: BOSS-owned property
  172, levels 1 and 2 respectively, receives automatic `403E` and continues.
- The same local log contains later gameplay through `00:14:48.610Z`.

These are observed local protocol exchanges, not a fresh interactive UI
acceptance run or evidence of production gameplay.

## Regression Results

Built the four construction/owned-property test targets, then ran:

```powershell
ctest --test-dir server/build --output-on-failure -R 'construction|owned_property' --parallel 4
```

All 4 tests passed (20.94 seconds):

- `native_richonline_boss_construction`
- `native_richonline_owned_property_tcp`
- `native_richonline_construction_resources`
- `native_richonline_construction_wire`

Coverage includes BOSS build/upgrade/cap, human accept/cancel/timeout,
waiting without premature reply or turn advancement, duplicate/late decisions,
default construction choices, licence consumption, and research continuation.

The first TCP run stopped in its preceding roadblock-card scenario because
the fixture marked all ground-card targets invisible while expecting success.
The fixture now supplies visible targets; gameplay visibility rules are
unchanged. The rebuilt full TCP test passed with this correction.

No production deployment or restart of the running game services was performed.

## Latest Log and IDA Recheck

Rechecked the same four client handlers through the current IDA-MCP instance
`4c30f33d33a1` and rebuilt all four regression targets before rerunning them.
All 4 tests passed again, including the encrypted TCP scenarios.

The latest local log is `server/data/logs/native-29592.jsonl` relative to
the repository root. Its last owned-property upgrade exchange is:

- `2026-10-10T00:21:43.565Z`: human actor 0 lands on its property 216,
  kind 11, level 2; the server records pending opcode 56 and sends `4013`.
- `00:21:44.604Z`: `0038` is received and answered with `403E` (5 bytes).
- `00:21:47.643Z`: `0039` is received and answered with `403F` (5 bytes),
  followed by the next turn's `4010` and movement messages.
- `00:21:53.003Z`: another movement completion receives `4013`, `4010`,
  and `420F`; subsequent retained records contain only opcode 1 heartbeats,
  through `01:00:55.528Z`.

The retained log therefore does not show an outstanding construction or
upgrade request at its end. Heartbeats alone do not establish the current
client UI state. This recheck required no further gameplay change and did
not restart either the server or client.
