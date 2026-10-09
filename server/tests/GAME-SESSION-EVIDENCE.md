# Game session boundary evidence

The native game listener now owns one nonblocking select loop and one
version-specific `GameSession` per TCP peer. Admission is parsed before any
299 message, and the complete descriptor is passed to the lobby-owned
authorization callback. A rejected descriptor closes that peer without
dispatching gameplay.

The Richonline admission payload is exactly 24 bytes and the legacy payload is
exactly 32 bytes. The 299 envelope uses no tail for Richonline and a four-byte
tail for legacy. The session preserves both the envelope metadata and the
decoded inner bytes for the callback; it never renames opaque admission fields
or logs their contents.

`PendingGameAdmissions` is versioned, owner-keyed, expiring, capacity-bounded,
single-use, and synchronized. A descriptor cannot be replayed, consumed by a
different client version, or accepted after its deadline. Replacing an owner's
pending descriptor invalidates the previous descriptor.

Validation on 2026-10-09:

- `richnet_game_session_tests`: partial/coalesced frames, both versions,
  authorization rejection, replay, truncation, expiry, replacement and
  simultaneous consume; PASS.
- `richnet_game_service_tests`: real loopback TCP, both versions, fragmented
  admission, coalesced gameplay, a stalled peer, a second concurrent peer,
  deterministic close and stop; PASS.
- Full candidate CTest: 17/17 PASS.

This is the transport and admission boundary. It does not claim room creation,
S2C22 ticket issuance, map startup, or BOSS gameplay. Those callbacks require
the corresponding lobby and game field evidence before being enabled in the
management runtime.
