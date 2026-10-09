# Original room/game handoff

2026-10-09. Original root RnClient.exe only. This connects the existing room directory, admission registry, game startup/session and dual-listener runtime through an explicit match strategy provider. The executable still needs a complete original BOSS strategy/configuration provider; this transport integration does not set `gameReady=true`.

## Protocol ownership

Fresh evidence in `protocol-analysis/ORIGINAL-HANDOFF-RECHECK-20261009.md` establishes S2C22 as the packed18 redirect, separate lobby/game connections, innerC2S10 as the two-byte board exit, S2C14 as actual lobby member removal, and G.flags0x800 as the room UI's running state. S2C15 is chat. Snapshot5's second DWORD remains opaque; it is not reused as a running flag.

The chosen server policy accepts the final ready transition with13, broadcasts26 with the owned running bit set, then sends each member their own22. Other configuration/extension bytes remain intact. This order follows known dependencies but is not claimed as an original-server capture. Duplicate ready packets do not append another ready entry or issue another ticket. Minimum membership is checked before creating a match. A failed provider restores each true ready member with96, preserving the prior cancellation order.

## Lifetime and concurrency

`OriginalRoomSnapshot` copies ordered user IDs, seats, teams, complete268-byte profiles, channel/game/owner identities and canonical room configuration. Its generation is a server-only monotonic value; it never occupies an unexplained wire field.

`OriginalGameHost` validates all returned player plans before preparing any externally visible redirects. Every member gets a unique nonzero reservation lease. It retains active match ownership after the one-use registry ticket is consumed. Invalid/replayed/expired tickets cannot consume another plan. Cancellation and expiration clean prepared strategies once; exceptions from cleanup are recorded and do not suppress later members' cleanup.

Admission deadline applies while any member remains unadmitted. Once all are admitted the game does not expire on that deadline. This is not a map-ready barrier or loading timeout: a multiplayer strategy must implement those against shared match state. Match callbacks serialize under the match lock and check cancellation even for heartbeat/poll traffic. User callbacks do not run under the host-wide map lock.

Game threads never call room mutation methods. Lobby `drain`, request and entry paths inspect match completion and apply notifications on the lobby thread. Pending expiration clears the running bit with26, emits96 for actual ready users and retains the room for retry. The current explicit whole-match cancellation policy removes every actual member with14 after any game participant has been admitted and the match ends. It does not claim to implement reconnect or surviving-player continuation.

`retire(generation)` atomically closes the match and returns final `admitted` state. This avoids the race where admission occurs between a pending-state observation and cancellation. Retiring releases host map/startup records; old socket callbacks retain a closed shared match and cannot mutate a later room reusing the same game/user IDs. Retired generations cannot be prepared again. Unknown retirement is idempotent; unknown status queries are errors.

`LobbyRuntime` accepts `OriginalRuntimeGame` as an optional, separate original-client provider. It starts the original game listener and binds its actual port before the lobby can issue tickets, preserves the lobby connection during gameplay, reports the listener port/status, and stops/joins listeners before final strategy cleanup. Missing provider retains the existing explicit not-configured rollback. The public status still distinguishes a listener from fully verified gameplay.

## Validation and remaining work

Three added suites cover host ownership/concurrency, direct room transitions, and real encrypted TCP through SQLite-backed LobbyRuntime. TCP follows login/create/ready→22→32-byte admission→4000→map-ready→4004→fixture opening→inner10→lobby14→new room with reused ID. It also exercises rejected/replayed tickets, silent pending expiry, failed-provider rollback and repeated stop. Direct tests cover observers, two-member tickets, minimum count, late cleanup, config/join guards and lobby disconnect. Barrier races cover simultaneous admission/retirement; repeated retire tests verify old generations are inaccessible.

Startup/actions in these scenarios are explicit test fixtures. They are not an original-client playthrough, full BOSS strategy, multiplayer gameplay synchronization or complete termination/reward settlement. Next production requirements remain a real resource/config-backed match provider, the authoritative original turn/landing/card/combat strategy, Lua wiring, remaining lobby businesses and actual original-client gameplay acceptance.

Final build-original and full CTest81/81 passed21.66s. Logs: `.omo/evidence/original-handoff-build.log`, `original-handoff-ctest.log`, `original-handoff-manager-checks.log`. .NET native lifecycle/account/config/log checks passed; manager screenshot evidence is `.omo/evidence/native-manager-254ee88ba2534125a449a7de8cc721a2`. No live user service was restarted.
