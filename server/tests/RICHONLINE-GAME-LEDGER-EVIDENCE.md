# Shared NEW game ledger

The shared ledger owns cash, deposit, tickets and reserve as distinct game currencies. It has no account database connection. Deposit and reserve are optional because the current board snapshot names its second word `opaque_second_balance`; the ledger does not infer either balance from that field. The session must construct each known value from verified resource/client behavior. Unknown deposit/reserve cannot be changed, even to guessed zero, through commit or nonzero adjustment.

`RichonlineGameLedger` supports 1..8 actors. Snapshot returns funds plus a revision. Commit compares both under a mutex; a stale value or ABA snapshot is rejected. Delta validation occurs before commit, with signed-i64-safe comparisons against zero and INT32_MAX. A failure cannot partly change another currency. A no-op preserves revision. Commit cannot change known/unknown status of deposit or reserve.

`RichonlineBossProperty(root, game_id, sharedLedger, stage)` and `RichonlineBossLandingState(game_id, sharedLedger)` now operate directly on that ledger. They hold no independent writable cash/tickets arrays. `cash()`/`points()` are read-only value projections for compatibility. Old constructors create isolated ledgers for existing callers/tests, explicitly leaving deposit/reserve unknown; runtime must use the shared constructors.

Property decisions reread current funds when completed, so a bank or event balance change while a purchase is pending cannot debit an obsolete wallet. Purchase still follows the evidenced strict cash > price test. Existing construction logic is unchanged, including the corrected default-building cap exemption and subsequent cap/skill upgrade checks. Landing points commit against the observed ledger revision. Existing `commit_points(expected,updated)` validates the expected point amount before whole-snapshot CAS and preserves other currencies.

BOSS static41/42 are accepted as no-card-reward landings under the existing empty-state guards, emitting only4013 and leaving every ledger field unchanged. These do not grant human card behavior.

## Validation

No shared CMake build, live service/client, account operation or IDA session was used. Standalone clang++ builds used C++20 and `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion`; current migrated sources were compiled directly and unchanged dependency libraries were read from the existing build directory. Outputs are isolated under `build-game-ledger-review/`.

- `ledger-tests.exe ../Richonline`: PASS shared-ledger CAS, stale/ABA protection, currency isolation, unknown balances, negative/overflow boundaries, atomic failed adjustments, actual-resource property/landing shared balances, pending purchase sees an intervening debit, BOSS41/42 completion.
- `richonline_boss_property_tests.exe ../Richonline`: PASS actual-resource property purchases, ownership and caps.
- `richonline_boss_construction_tests.exe ../Richonline`: PASS construction, upgrades, licences and timeout decisions.
- `landing-tests.exe ../Richonline`: PASS existing point rewards, unsupported-context protection, overflow and timing compatibility. This standalone run linked existing turn-engine objects; it is not a fresh full-engine build claim.

Root integration needs `src/gameplay/ledger.cpp` in the appropriate shared target, a single ledger per session, the new property/landing constructors, and explicit known initial deposit/reserve evidence. Bank/other-event handlers must commit returned deltas/snapshots to that same ledger before transmitting success.
