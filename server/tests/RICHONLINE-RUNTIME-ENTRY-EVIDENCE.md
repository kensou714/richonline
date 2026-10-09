# New client native runtime integration — 2026-10-09

The C++ control entry now loads the explicit BOSS host and turn policy into `LobbyRuntime`. Missing either policy section fails startup; absence of both retains management/lobby-only operation. `gameListenerReady` reports the socket, while `gameReady` remains false.

## Implemented boundary

- Actual `Richonline/Map/BS_1_1.emp` topology and initialized participants supply mode, synthetic identity, road degree and collision state to the landing resolver.
- Empty-state synthetic BOSS in mode3 can finish static7, static8 and no-static endpoints with no property, no other actor, degree1..2. It sends the six-byte consumed/replayed 4013 prefix before the next4010/420F. Other landings fail with explicit context and reason.
- Initial leftward routes of1/2/3/6 steps reach235/234/233/230 and complete. At233 the synthetic BOSS follows the user's no-card-inventory rule:4013→4031(-1)→next4010/420F. Four/five steps reach initially unowned property216: resource price100 and strict cash>price permit4013→4020(1), debit100 and assign owner1. Equal/insufficient cash emits4013 only, matching the local automatic completion branch. Later owned-property visits remain unsupported.
- Position230 is **runtime static7**, not raw static-1: the map loader applies `special_xy`. The new test locks that distinction.

Evidence: `protocol-analysis/richonline-rebuild/game/startup-flow/landing-property/`. Local6080 queue insertion precedes a subsequently queued network4010; this does not permit bypassing an event that waits for a real server response.

Shop evidence: `game/startup-flow/static10/`. New660B00 consumes a signed selection byte at+4; -1 closes an absent/inactive shop panel safely, does not read stock and does not require4030. The five-byte response is a consumed-prefix compatibility policy. This does not implement human shopping or its timer.

The `richonline_chance` library reads new BwNews, Prop, CombCard and map eligibility resources. The optional runtime policy now connects category5/event17/card1038 to human static68 landings:4013→4096, followed by the next turn. It mirrors eight inventory slots; a full inventory still emits the reward so the native full-card popup completes its local phase without server mutation. Enabled combinations are rejected; BS_1_1 excludes504, so eight1038 cards do not combine. Unknown6/7 remain explicit policy bytes.

Controlled inventory dice use C2S103, with selected die at+6, slot at+4 and bank0 at+5. A valid use emits40B7→4011 directly and consumes one slot only after route construction succeeds; it does not wait for a secondC2S10. Empty slots and unsupported paidC2S22 recover controls with400B and log the rejection. The recovery is a proven UI capability used as local compatibility policy, not a recovered official error response. Paid balance settlement remains unimplemented and no charge is applied.

Contracts: `game/startup-flow/controlled-dice/`, `property216/`, `landing-static68/`, and `static10/` under `protocol-analysis/richonline-rebuild/`.

## Executed checks

Latest integrated CMake build passed. Full CTest: **81/81 passed**,7.30 seconds. This includes concurrent original-client handoff changes. The preceding78/79 snapshot failed `native_original_room_service` with `frame_payload_wrong`; its exact historical differing frame was not captured, so this report does not claim a proven root cause for that failure. Changed runtime, turn engine, cards, property, chance, controlled-dice and TCP test LSP diagnostics are clean.

Actual encrypted TCP covers card reward at114, BOSS234, selected die3 moving114→130→146→162, slot consumption, recovery and duplicate-phase rejection. Resource tests cover property216 price/ownership/strict affordability and all first BOSS endpoints230..235. These are transport/resource proofs, not actual native-client interaction. Card-turn regression first failed with `richonline_boss_landing_unsupported` before the runtime integration.

Earlier isolated probe6916 on187xx stopped cleanly. The latest deployment uses a fresh online backup `accounts-1791497225023339.sqlite3` in `local-server/runtime/native-boss-live-20261009/`. Idle diagnostic37636 was stopped with exact instance verification. Pinned candidate38160, instance38160-264800720639000, reports lobby18600/game18602/black18604/http18680 ready and `gameReady=false`. Startup stderr is empty. Source diagnostic database and executable remain retained; the deployed EXE is separate from the active build directory. No authenticated client session was observed at deployment.

Deployed server SHA256: `a3ce3e3798e06bd44850f6adef67bfa3fff193e183f023bfb378ba405c0133fd`.

## Open work

Latest continuation supersedes the81/81 snapshot above: human property216 accept/decline/timeout and late-click handling are implemented, including host/registry polling. Build passes, latest suite83/84 with one newly introduced original-profile BOSS type70 failure. Deployed purchase binary is44128 / SHA18a4e4290b4dcf47725fc2a83fdfe85789f7738e8adef88a62e8cd14c67dd0f3, same186xx endpoints anddata directory. See `RICHONLINE-PURCHASE-EVIDENCE.md` for exact scope, red/green evidence, backup and actual .NET-manager checks (both profiles9/9, GUI interaction still unverified).

These checks do not prove real-client login, channel entry or full playability. Native UI capture previously failed; the channel CRT issue is not resolved by this report. Human properties other than216, later owned-property events, shop transactions/timers, status effects, cards other than1038, paid dice, victory and persistence remain incomplete. Unknown wire bytes are explicit compatibility policy with provenance, not recovered business semantics. The candidate is not the default manager package and has not replaced root executables.
