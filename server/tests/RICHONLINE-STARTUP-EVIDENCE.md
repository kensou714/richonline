# Richonline startup integration evidence

2026-10-09. New-client target: `Richonline/RnClient.exe`, SHA256
`cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77`.
All product code in this change is C++; the management interface remains .NET and persistence SQLite.

## Boundaries implemented

- `richonline_board.cpp` encodes 0x4000 as a 20-byte header plus 16 bytes per absolute participant slot, and 0x4004 as a 12-byte header plus 12 bytes per absolute slot. The local slot is distinct from the lobby identity. Opaque header bytes and the unknown floating-point field must be supplied explicitly.
- The ten signed bytes copied to player+272 are building skill caps, as confirmed by 0x7F46B0, 0x7F74B0 and their building-upgrade consumers. The native codec does not choose their values. The last byte of each participant record remains opaque.
- `richonline_game_startup.cpp` sends initialization after admission, handles opcode1 as an initialization notification, and waits for opcode0 before sending the snapshot and calling the game strategy. Treating opcode1 as insufficient for loading completion is a local server policy grounded in the client's thread order, not a capture of the original server.
- S2C business packet+2 is the game-server ID. C2S action+2 is the low16 calendar counter. 0x4004+4 supplies the latter; a normal 0x4010 progression increments it. The callback supports the normal active-slot progression path; richer status/animation branches still require their own gameplay state implementation.
- `richonline_game_registry.cpp` registers every room member before returning any S2C22. Complete descriptors are version-specific, expiring before admission, single-use and cancelled on room abandonment. Active messages and cleanup are serialized per entry. Shutdown releases pending and active plans.
- `LobbyRuntime` can own the lobby, auxiliary services and an optional game provider/listener. A provider must explicitly supply all game plans. Its manager must match the currently published channel key 0 (S2C3+32 and S2C9+4 in `server_lobby_adapter.cpp`). Port0 requests an OS-assigned listener port; the provider receives the actual bound port.
- `gameListenerReady` describes listener state only. The administrator service still reports `gameReady=false`: no complete production BOSS strategy has been installed.

## Verification

The first startup-context regression failed with `richonline_game_action_instance_mismatch` when a valid calendar-counter input was compared against the game ID. It passed after separating both domains. The test deliberately uses different game-ID and calendar values and covers normal-turn wraparound, special-turn preservation, early inputs, duplicate loading notifications and cleanup.

`native_richonline_room_runtime` runs actual loopback TCP listeners with isolated SQLite accounts. It verifies:

1. Two encrypted lobby sessions create/join/prepare/cancel/leave a room.
2. Disconnect delivery is ordered 14 → 57 → 55 for the final room member.
3. An explicitly injected game fixture delivers S2C22, accepts type0, emits 0x4000, processes1 then0, emits0x4004 and0x4010, and accepts an action with the incremented calendar counter.
4. Closing the game connection releases the plan once and resets lobby readiness through96.

This fixture uses synthetic E88, positions, skill values and opaque bytes. It proves server transport/lifecycle behavior, not successful resource loading or real-client playability. No production account credentials, login bodies or full process memory were recorded.

Latest integrated strict build and full CTest passed47/47. Integrated server SHA256: `aa96119848f656bb295a3d9328c2792e03cc883deceec5b9f54266445fe8d988`. Earlier40/40,37/37 and isolated7/7 runs are historical checkpoints. The real TCP test also verifies canonical23/26 map edits and10/18 character selection with SQLite persistence. The independently packaged administrator candidate pins its own previously tested server SHA in `admin/evidence/CANDIDATE-PACKAGE-QA.md`; it is not silently updated when the shared build changes.

The second-page character regression first failed `model_selection_invalid`, then exposed the SQLite `CHECK(model BETWEEN 0 AND 4)` constraint. New-client selection now accepts the resource-backed IDs0..8 at the directory, profile and database boundaries. Original-client storage remains0..4. Version5→6 migration backs up existing databases and preserves additional columns, generated columns, indexes, triggers, views, foreign keys and balances; an injected final-version failure verifies transaction rollback. No production database was migrated for this check.

Fresh lobby IDA evidence disproved the previous dynamic5→12 announcement. Dynamic creation now sends10 to all admitted observers, whose native handler attaches the owner and builds the UI room cache. Initial late-observer snapshots remain7→5→12/13 but now precede the existing first30 completion; regression tests failed `create_response_wrong` and `channel_completion_precedes_existing_room_snapshot` before these fixes. No repeated30 refresh is fabricated.

`richonline_boss_startup` now reads the actual new BS_1_1 map and BossWar/Prop resources. It verifies map signature, E88, public mode/count, empty equipment prerequisites and slot identity. Tests cover real funds/skill layout and deliberately changed resource topology/equipment effects. Spawn placement is an explicit local deterministic policy; resource tests are not real-client playability evidence.

## Source evidence

- `protocol-analysis/richonline-rebuild/lobby-room-flow/consumer-detail/`
- `protocol-analysis/richonline-rebuild/lobby-room-flow/admission/`
- `protocol-analysis/richonline-rebuild/game/startup-flow/init-fields/`
- `protocol-analysis/richonline-rebuild/game/startup-flow/room-to-game/`
- `protocol-analysis/richonline-rebuild/game/startup-flow/init-bridge/`
- `protocol-analysis/richonline-rebuild/lobby-room-flow/room-edit/late-observer.md`
- `protocol-analysis/richonline-rebuild/game/startup-flow/resource-init/`
- `protocol-analysis/richonline-rebuild/game/startup-flow/movement-wire/`

Real-client channel-entry CRT failure, additional map/BOSS initialization, actual gameplay strategy, complete room metadata editing and GUI interaction QA remain open.
