# Game admission codec evidence

Scope: pure native C++ type-0 admission parser/encoder. This change does not
connect the codec to `service.cpp`, change admission policy, or establish a
playable game. IDA inspection was read-only: no names, types, bytes or database
contents were changed.

## Wire boundary and neutral fields

Both APIs require an explicit `ClientVersion`. Offsets below are relative to
the payload; DWORDs are little-endian and `opaque8` is copied byte for byte.

| Payload offset | Size | API field | Richonline | Legacy |
| --- | --- | --- | --- | --- |
| +0 | 4 | `id0` | present | present |
| +4 | 4 | `id1` | present | present |
| +8 | 4 | `id2` | present | present |
| +12 | 8 | `opaque8` | present | present |
| +20 | 4 | `field20` | present | present |
| +24 | 4 | `legacy_fields[0]` | absent | present |
| +28 | 4 | `legacy_fields[1]` | absent | present |

Richonline accepts exactly 24 payload bytes (32 total wire bytes), legacy
exactly 32 (40 total). The outer frame type must be 0. Missing legacy fields
cannot be encoded as implicit zero placeholders; present legacy fields cannot
be silently dropped for Richonline. Unknown versions are rejected. The codec
does not validate identifier or opaque-field business meanings.

## Richonline IDA evidence

Binary: `Richonline/RnClient.exe`, re-read on 2026-10-09.

- `0x87A2B0` admission constructor: `0x87A2E8 push 18h` allocates a 24-byte
  payload. `0x87A31D`, `0x87A324`, `0x87A32B` call `0x60D91B` to append the first
  three DWORDs. `0x87A332` calls `0x61002B` for the next eight bytes;
  `0x87A339` calls `0x6113A4` for the final DWORD. The original instructions
  load full DWORD arguments; Hex-Rays' `char` parameter types are misleading.
- Copy helper thunks resolved freshly: `0x60D91B -> 0x868530` copies 4 bytes,
  `0x61002B -> 0x87D000` copies 8 bytes, and `0x6113A4 -> 0x8795F0` copies 4
  bytes through `0x60E136`. Constructor argument 4 is emitted after arguments
  5/6, so the copied eight bytes precede the final DWORD on the wire.
- Base constructor `0x87C9C0`: `0x87C9FB add eax,8`; `0x87CA20 push 0` and
  `0x87CA25/0x87CA2C` write type 0 and the total length. There is no lobby magic
  or lobby payload transform in this game frame.
- Connection caller `0x87A110` supplies the three leading IDs from separate
  getter chains: `0x604DB1 -> 0x82BDA0` reads object+12;
  `0x60C043 -> 0x846BD0` reads object+124; `0x602D63 -> 0x82BEE0` reads object+8.
  Caller stack arguments 3/4/5 supply constructor arguments 4/5/6. These source
  locations do not justify renaming the common fields to session tokens or
  asserting an authorization meaning.

Earlier export references:
`protocol-analysis/richonline-rebuild/transport-send/transport-evidence.txt`
(constructor section begins at line 4479, base section at line 4746), and
`protocol-analysis/richonline-rebuild/lobby-receive/0x60cf66.c` / `.asm`.

## Legacy IDA evidence

Binary: root `RnClient.exe`, re-read on 2026-10-09 using the existing GUI IDB.

- `0x7961A0` populates a contiguous eight-DWORD local block. The first three
  words are getter results; the next two words come from input+4/input+8, then
  input+0. `0x79620F` / `0x796216` explicitly store the final two DWORDs at the
  positions corresponding to payload+24/+28.
- `0x796241 sub esp,20h`, `0x796244 mov ecx,8`, and `0x79624E rep movsd` copy
  this exact 32-byte argument block; `0x79625A` calls thunk `0x5C3140`.
- `0x5C3140 -> 0x7A1570` copies eight DWORDs from its argument block at
  `0x7A167F mov ecx,8`, `0x7A1684 lea esi,[ebp+arg_4]`, `0x7A1687 rep movsd`.
  `0x7A1890` adds 32 to the base/header size, and type getter `0x7A1900` returns
  type 0. The observed caller writes zeros in the extra positions; the codec
  represents those positions explicitly and also preserves nonzero values.

Existing cross-check: `protocol-analysis/GAME-LOBBY-ENTRY.md:75` and
`local-server/game_transport.py:40` describe the corresponding 32-byte layout.

## Validation

`game_admission_tests.cpp` uses independent full-wire fixtures for both
versions, including high-bit IDs, mixed opaque bytes, and nonzero legacy
fields. It checks every payload length 0..40 against each selected version,
cross-version rejection, wrong types, unknown versions, missing/extraneous
legacy fields, explicit zero legacy fields, DWORD boundary values, and all
256 opaque-byte bit patterns. The full-wire fixtures exercise the existing
frame codec without lobby magic.

Standalone strict-warning build and test on 2026-10-09: compiler exit 0 with no
diagnostics; test exit 0, output `game admission fixtures passed`. Compiler:
LLVM-MinGW `clang++` installed through WinGet. No CMake or service integration
was changed by this work.

```
clang++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion -I native-server/include native-server/src/frame.cpp native-server/src/game_admission.cpp native-server/tests/game_admission_tests.cpp -o F:/richnet-game-admission-tests-79f802b41add.exe
F:/richnet-game-admission-tests-79f802b41add.exe
```
