# New-client native BOSS movement milestone

2026-10-09. Client SHA256 `cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77`.
Product modules use C++20, SQLite and the existing .NET8 manager. IDAPython is used only for binary analysis.

## Implemented boundaries

- `richonline_movement_wire`: separate typed C2S10/11/12/28/2A, bounded 36-direction4011, explicit opaque spans, round anchor4010, and the proven420F(-1) empty-status continuation. Selected serializer lengths are local compatibility policies, not recovered historical fixed lengths.
- `richonline_route`: actual EMP topology, walkability, static type, signed property reference and bounded ordinary routes. New-client terrain/property evidence is independent of old gameplay parsers. Only the proven compatible EMP/KPD container decoder is reused. Dynamic objects and static9/61/67 are explicitly unsupported here.
- `richonline_boss_host`: optional strict configuration, resource-based initialization, per-game SQLite skill revision snapshot, random admission tokens, exact session registration and cleanup. Missing strategy or room prefix is rejected.
- `richonline_boss_turns`: BOSS slot1 acts first; fixed round anchor1. Empty turns emit4010 then420F(-1). BOSS movement is sent immediately; human movement waits for C2S10. Both require matching actual endpoint11. Every landing calls a mandatory resolver that explicitly completes, waits for an event, or finishes the game. Special movement reports cannot act as ordinary endpoint acknowledgements.

The turn engine is deliberately limited to empty statuses and no dynamic objects or paid movement. The landing context includes property_ref so a static tile value cannot conceal a property event. No default landing resolver was added. Production `control.cpp` still has no complete Richonline strategy and reports `gameReady=false`; the new host library is not silently installed into the running service.

## Verification

The first engine test failed because the new API did not exist. The green sequence was corrected using fresh IDA evidence to require420F after4010;4010 alone does not enable dice controls.

`native_richonline_boss_turns_tcp` uses actual loopback GameService, the configured host/registry, SQLite, actual BS_1_1 resources and encrypted299 framing. It verifies:

1. Admission→4000→C2S1→C2S0→4004→4010→420F→4011.
2. BOSS236→235 with calendar4568; human115→114 with calendar4569; next BOSS starts from235.
3. A resolver waiting on an explicit fixture event cannot advance early; duplicate stop cannot repeat landing.
4. Sending GmsvID1234 instead of calendar counter fails with `richonline_game_action_context_mismatch`, without reaching the resolver.
5. Disconnect removes the registry entry and performs cleanup exactly once.

The TCP landing resolver only records/waits. It does not implement actual buildings, shops, cards or NPCs. The test is transport/state evidence, not proof that the native client renders or completes gameplay.

Full strict build and CTest **57/57 PASS**; final changed implementation/test LSP checks report no diagnostics. A transient concurrent original-shop test narrowing error was resolved by that workstream before this full run. C disk exhaustion was bypassed for the build/tests by setting only the command's TEMP/TMP/TMPDIR to the candidate's F-drive runtime-tmp directory.

Verified artifact SHA256:

| Artifact under build-integrated-candidate-20261009 | SHA256 |
|---|---|
| RichOnline.Server.exe | `23bc5e572d5e0eb362a385430585d5c60bc8b17d8194f1083160fd60e22350a4` |
| richnet_richonline_boss_turns_tcp_tests.exe | `e2df9c3011baf41619d58bd92a859652ece6563029f26f751f1ba73403b263bc` |
| librichnet_richonline_boss_startup.a | `2b6087f6910f4b1b3e82e9b0e1b8cd47eebda575fc70e2dd207bea569bf832a3` |
| librichnet_richonline_boss_host.a | `dc1e3c9f36ff7abcfde57317aa8e9230021db66b015c42ef47d95202bab76e2c` |

## Remaining work

Full landing/event handlers, controlled states and dynamic map objects must precede production host enablement. New-client actual channel CRT reproduction and native-client/manager interaction QA remain unverified. Existing deployed EXEs and live user databases were not changed by this milestone.

Source evidence: `protocol-analysis/richonline-rebuild/game/startup-flow/turn-policy/` (135 functions), `movement-wire/`, `resource-init/route-property/`, and `protocol-analysis/richonline-rebuild/lobby-crash-dumps/`. The historical dumps establish two earlier null-channel access violations, not the current CRT termination cause.
