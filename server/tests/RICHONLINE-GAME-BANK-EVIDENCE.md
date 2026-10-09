# NEW in-game bank module

Implementation scope: `include/richonline_game_bank.hpp`, `src/gameplay/bank.cpp`, `tests/richonline_game_bank_tests.cpp`. No account SQLite bank behavior is reused. No live client, server, account action or additional IDA session was used. Root owns the engine/session/route/CMake integration.

## Evidence contract

`protocol-analysis/richonline-rebuild/game/startup-flow/intermediate-effects/CONTRACT.md` is the governing NEW static contract. Relevant raw routines: `7BBE60` (decision sender), `65E1B0` (bank admission), `660320` (transaction and continuation), `7BB530` (timeout).

- C2S `0x28` is exactly 6 bytes: opcode, calendar low16, signed map position. It identifies an intermediate bank interruption, not a completed route.
- C2S `0x27` is exactly 12 bytes: opcode, calendar low16, action u16, two unassigned bytes, amount i32. Actions are deposit 0, withdraw 1, exit 2. Request padding is preserved and never required to be zero.
- S2C `0x4018` uses an 8-byte compatibility envelope: game id, position, passing flag 1 or landing flag 0, caller-supplied unread padding. Eight bytes are necessary for the client's internal requeue copy; the last byte has no proven semantic value.
- S2C `0x402A` uses a stable 12-byte compatibility envelope. Its two unread bytes are supplied explicitly through `RichonlineGameBankWirePolicy`, never described as known fields. Exit amount 0 has actual client-sender evidence and is not unknown-field padding.
- The client expands withdraw-all before sending: `7BBE60` replaces local `(1,0)` with `(1,actual_deposit)` or `(2,0)` when empty. A received wire withdraw amount 0 therefore is not reinterpreted as withdraw-all by this module.

## Explicit emulator policies

Negative/zero transaction amounts, insufficient source money and destination signed-i32 overflow resolve `402A(action2,amount0)` with unchanged balances. The client proves this exit branch; no historical dedicated error packet or error code is claimed. Unknown action values, malformed packet lengths/opcodes and wrong calendar counters remain protocol errors.

The module enforces the client UI's 8000ms pending deadline. A click at or after the deadline resolves exit without transfer. Synthetic BOSS visits immediately emit `4018` then `402A` exit to synchronize the client's passing/landing flag and use the proven continuation path. This no-transaction BOSS behavior is a selected emulator policy; the historic server's BOSS bank strategy is unknown.

The module reports a typed before snapshot (`result.entry.balance`) and after snapshot without writing a global ledger. Caller must validate actor, location, bank availability/control status and saved route before `begin`, then atomically compare/commit the returned balance snapshot before sending replies. A passing completion resumes the saved route without a new `4011` or new actor. A landing completion continues the remaining landing phases, including final junction; it is not a generic end-turn.

Duplicate and stale requests after completion must be handled by the engine's retired-decision routing. This class clears a completed pending operation and does not independently replay a response or apply it twice.

## Isolated validation

Command, run from `native-server`:

```sh
clang++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion \
  -Iinclude tests/richonline_game_bank_tests.cpp src/gameplay/bank.cpp src/frame.cpp \
  -o build-game-bank-review/bank-tests.exe
build-game-bank-review/bank-tests.exe
```

Result: exit 0, `PASS NEW game bank parsing, conserved transfers, safe exit and continuation`.

Tests cover exact/truncated/oversized layouts, opcode/action/counter/position/actor boundaries, arbitrary padding, deposit and withdrawal, both continuation types, full source transfer at INT32_MAX, negative/zero amount, insufficient source, destination overflow, unchanged balances on refusal, explicit exit, 7999ms/8000ms timeout, late click, synthetic visit and no duplicate poll/mutation.

Red/green artifacts under `build-game-bank-review/`:

- `red.log`: test/header existed before implementation; missing bank symbols failed linking as expected.
- `build.log`, `green.log`: strict final build and passing run.
- `bank-conservation-mutant.cpp`, `mutant-build.log`, `mutant-red.log`: an isolated copied implementation was changed to credit one extra deposit unit. It compiled and the same test executable failed `transaction_not_conserved` with exit 1. The production source was never changed by this mutation check.

These tests verify the independent state machine and byte output. They do not claim actual-client bank UI or engine continuation is verified until root integrates and tests those paths.
