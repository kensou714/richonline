# RichOnline native service and protocol core

## NEW map and gameplay layout (2026-10-09)

The current NEW runtime selects an immutable package by room map name and category.
See [map packages](src/maps/README.md) and [shared gameplay](src/gameplay/README.md).
Black Beibei and Zhao Ling'er have separate packages; their duplicate numeric map
index 11 does not imply interchangeable resources. Shared property rules receive
the selected stage's prices, default building, caps and synthetic skills.
Zhao remains gated while its remaining events are incomplete. `gameReady:false`
still reflects incomplete full gameplay. The latest integrated build has98
passing tests, including map isolation, portal routes and encrypted junction flows.
The broader protocol goal is recorded in
`../protocol-analysis/richonline-rebuild/coverage/GOAL.md`.

## Native rewrite status (2026-10-09)

`RichOnline.Server.exe` now provides the current-user-only administrator pipe,
SQLite accounts/settings/audit/backup, and compatible scrypt password verification.
The compiled .NET WinForms application lives in `../admin`. This path has no
Python runtime. The native service currently reports `gameReady:false`: game
listeners, lobby state and full BOSS gameplay have not yet been migrated.

Build with the existing CMake/Ninja toolchain below, then run
`ctest --test-dir native-server/build-ninja --output-on-failure` from the workspace
root. `native_codec`, `native_storage`, and `native_control` exercise fixed codec
fixtures, real SQLite transactions and real Windows named-pipe processes.

Launch headless with absolute paths:

```text
RichOnline.Server.exe --data-dir F:\richonline-native-data --pipe richonline-admin
```

See [CONTROL-PROTOCOL.md](CONTROL-PROTOCOL.md) for commands and boundaries.
The data directory has a process lifetime lock. It defaults to a separate native
database in the GUI. Do not point this experimental build at the live legacy DB.
An explicit `--import-db SOURCE --data-dir EMPTY_TARGET` uses a read-only source
and SQLite backup, preserving unknown tables and existing password material.
The import target must not already exist; no automatic account reset is performed.

Native codec now accepts explicit `ClientVersion::richonline`: the 299 envelope
has no old four-byte tail. The legacy default is retained only for historical
comparison. [tests/CODEC-EVIDENCE.md](tests/CODEC-EVIDENCE.md) documents machine
arithmetic and direction-dependent negative-key behavior from the new binary.

The sections below describe the older codec CLI; its Python comparison harness
is historical and is not required to build/run the new service or manager.

This C++20 executable checks the recovered transport codec and evaluates a
trusted Lua BOSS attack policy. It reads commands from stdin and writes results
to stdout. It does not listen on a TCP port, start the client, or replace the
live Python lobby, game service, account database, or GUI.

## Build

Requirements: CMake 3.24+, a C++20 compiler, and a build generator. The initial
configure downloads official Lua 5.4.8, verified with SHA256
`4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae`.
Lua is compiled into a static library; no Lua DLL is required.

Verified Windows toolchain: CMake 4.1.2, clang 22.1.3 / LLVM-MinGW, Ninja 1.13.2.
From Git Bash at the repository root:

```bash
cmake -S native-server -B native-server/build-ninja -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$PWD/native-server/build-tools/ninja.exe" \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build native-server/build-ninja -j 4
uv run native-server/check_conformance.py
```

The local Ninja binary has SHA256
`07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65`.
With Ninja on PATH, omit `CMAKE_MAKE_PROGRAM`. The compiler flags above are for
LLVM-MinGW; other C++20 toolchains can use their own CMake compiler selection.

## Command interface

One command per line; blank lines are ignored. Hex is contiguous, without a
`0x` prefix. `-` denotes absent lobby key or empty bytes. Channel names are
`lobby_c2s`, `lobby_s2c`, `game_c2s`, and `game_s2c`. Keys currently accept only
the nonnegative int32 subset. Game channels and plaintext handshakes reject a
supplied lobby key. A diagnostic goes to stderr with exit status 1 on failure.

| Command | Result |
| --- | --- |
| `frame CHANNEL KEY|- HEX` | Decode and rebuild the outer wire frame |
| `frame_decode CHANNEL KEY|- HEX` | Decimal uint32 type and plaintext hex |
| `frame_encode CHANNEL KEY|- TYPE HEX|-` | Encode explicit uint32 type and payload |
| `stream CHANNEL KEY|- HEXCHUNK...` | One rebuilt frame per line after incremental parsing |
| `inner_encode PLAINHEX FILLERHEX` | Inner encoding with explicit caller-owned filler |
| `inner_decode HEX` | Decoded inner plaintext |
| `envelope HEX` | Decode and rebuild the type299 constructor profile |
| `envelope_decode HEX` | Signed inner type, signed mode, encoded bytes, four-byte tail |
| `policy "PATH.lua" DRAWS,CSV` | Ordered attack choices from the Lua policy |

Example input, entered into `build-ninja/richnet_protocol.exe`:

```text
frame_encode game_c2s - 7 616263
frame_decode game_c2s - 070000000b000000616263
inner_encode 0100 11223344
policy "native-server/rules/boss.lua" 90,0,0,0,0
```

The first two results are `070000000b000000616263` and `7 616263`.
The policy example returns `weapon:1046`, then three `idle` lines. Paths are
UTF-8 and may contain spaces when quoted. Relative paths resolve against the
process working directory.

## Preserved Boundaries

- Outer length is little endian and includes the eight-byte type/length header;
  lobby C2S and game S2C additionally carry the directional magic prefix.
- The 1 MiB frame limit is a local resource policy, not a recovered server limit.
- Inner encode accepts 2..509 plaintext bytes and exactly `plain_length + 2`
  filler bytes. Decode also accepts the canonical 510-byte case.
- Unknown business payloads remain bytes. No invented field values are inserted.
- Type299 uses signed int16 inner type, uint16 encoded length, signed int8 mode,
  encoded data, and an explicit four-byte tail. The `17 + encoded_length`
  profile is a compatibility candidate, not a verified historical S2C capture.
- The stream decoder rejects a partial frame at end of input.

## Lua Policy

The default policy performs four independent attempts with 80% idle, 10% mine,
and 10% weapon. Successful weapon draws choose from IDs 1046, 1063, and 1075.
There is no default per-category cap or inventory dependency. Four mine or four
weapon results are valid. The injected draws are zero-based and must exactly
match the calls consumed by the policy, including weapon selection draws.

The module returns `config` and `select_attacks(config, rng)`. Configuration
supports 0..8 attempts, integer weights summing to 100, and a unique supported
weapon pool. This executable only selects attack categories: legal targeting,
visibility, controlled states, blast effects, turn scheduling, and wire
broadcasts still belong to the live server.

Lua files are trusted executable code and use the standard Lua libraries.
This is not an untrusted-script sandbox. The test harness passes deterministic
draws; production randomness is not implemented by this stdin tool.

## Verification

The normal NEW mode3 BOSS result byte18 compatibility accepts exactly the original
`cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77` and the verified
Direct3D flags-only derivative
`a23410e79637e312c932f861176d8d81cd1fd5d222a286f279feccdece6263c2`.
See [the scoped compatibility evidence](../protocol-analysis/richonline-rebuild/game/settlement/CLIENT-COMPATIBILITY.md)
for the original consumer audit and reproducible complete-file diff verification.
Other hashes and game modes remain rejected by the compatibility helper.

`check_conformance.py` runs both executable suites. The 150 cases cover direct
encode/decode comparison with `local-server/codec.py`, unknown payloads, keyed
lobby transforms, fragmentation/coalescing, limits and malformed input, signed
envelope fields and nonzero tails, all 100 probability buckets, configuration
overrides, RNG errors, and non-string Lua errors.

Test vectors are independently constructed inputs, not actual wire captures.
The rankings fixture is a genuine decoded client resource explicitly placed
inside a constructed unknown-type frame. This distinction is deliberate: the
tests establish codec consistency, not completeness of recovered gameplay.
