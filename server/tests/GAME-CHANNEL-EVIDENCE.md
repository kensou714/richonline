# Richonline game admission channel isolation

The new-client admission analysis in `protocol-analysis/richonline-rebuild/lobby-room-flow/admission/fields.json` identifies packet offset 8 as a full DWORD manager key from `context+4.obj+12`, via `604DB1 -> 82BDA0`. Packet offset 12 is the local room key from room object `+124`. Both are required; a room key alone does not identify a game across separate channel directories.

`RichonlineRoomSnapshot.channel` carries the selected manager key into game preparation. The registry tracks `(channel, local room key)` for cancellation, expiration, disconnection and shutdown. Expected game admission uses the snapshot channel as `id0`; the BOSS host uses the same channel when binding its startup callbacks. Startup logs include channel and room. The redirect remains 18 payload bytes, and game admission remains 24 payload bytes; no new wire field was introduced.

The explicit two-argument `cancel_room(channel, key)` and `has_room(channel, key)` APIs are used by channel-aware lobby dispatch. Existing single-channel overloads use the constructor's manager only as their default channel; it no longer overrides the actual snapshot's admission identity.

`richonline_game_channel_tests.cpp` deliberately prepares three single-player rooms with identical local key, actor, token and extra values but distinct channel IDs and lobby connections. This distinguishes channel isolation from accidentally relying on random tokens. It checks all three admissions, rejection of an unknown channel, cancel/disconnect isolation, independent pending expiry, and exactly-once shutdown cleanup. A non-small manager value verifies that all four DWORD bytes remain present.

The existing registry tests retain concurrent action/poll cancellation coverage. `richonline_boss_host_tests.cpp` adds real-resource provider preparation for channels 0, 1 and 2, manager substitution rejection, successful startup, and continued map-ready processing in another channel after cancellation. These are isolated server-side tests, not evidence of native-client playability or multiplayer BOSS support.
