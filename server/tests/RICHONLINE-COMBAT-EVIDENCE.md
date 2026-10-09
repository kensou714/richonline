# NEW combat planner verification

IDA evidence: `protocol-analysis/richonline-rebuild/game/combat-new/CONTRACT.md` and adjacent raw JSON. No old-client packet layouts were reused.

Standalone command from native-server:

```
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion -I include tests/richonline_combat_tests.cpp src/gameplay/combat.cpp src/frame.cpp -o tests/richonline_combat_tests.agent.exe
tests\richonline_combat_tests.agent.exe
```

Result: both exit0, `richonline combat planner tests passed`.

Covered: three-day mine lifetime/red day, exact401E/4017 ordering, duplicate-day idempotence and stale/gap rejection, mine owner retention, no duplicate4017 for stepping or missile chains, cash→deposit debit preserving tickets/reserve, exact-total bankruptcy, shared status multipliers, minimumdamage1, normal chain bonus, valid1076 prepared consumption and forged-plan rejection, unknown-bank refusal, BOSS40BF actor field and bank=-1 presentation, sleepwalking/frozen/visibility rejection. Follow-up tests cover verified nuclear damage, safe nuclear self exclusion, eight actor slots, mode3 property effects and complete resolved modifier order; see `NUCLEAR-AND-MODIFIERS.md`.

Shared combat coordinator tests are documented in `RICHONLINE-COMBAT-SESSION-EVIDENCE.md`. Session adapters must still supply authoritative topology, resolved modifiers, normalized property changes and fatal settlement ordering. No UI/computer-use or live-client test performed.
