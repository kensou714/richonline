# NEW BS_1_1 owned-property repair — 2026-10-09

## Observed failure and corrected behavior

Live log `local-server/runtime/native-boss-live-20261009/logs/native-63848.jsonl:409-412` recorded the BOSS's C2S0011 at terrain231, property216, followed by `richonline_boss_landing_unsupported` and game connection closure. The old property resolver accepted only unowned land and returned no result for every owned property.

Owned empty land now emits4013 and either awaits the human0037 decision or automatically constructs the scenario default for the BOSS with403D. Owned built land below both the scenario cap and actor skill emits4013 and either awaits human0038 or automatically upgrades with403E. At the cap it emits4013 and proceeds. Shared terrain references231/232 mutate one property216 record. Ownership and cash are unchanged by construction/upgrade; nondefault first construction consumes exactly one valid licence from the existing game card inventory.

Human confirm, cancel and timeout complete the pending decision before the next actor's4010/420F. Matching late or duplicate decisions are retired without emitting a second building mutation. Invalid licensed choices resolve to no-build. First-build requestFF maps to the scenario default as explicit server policy because the NEW responseFF handler would skip construction.

## Protocol provenance

NEW `Richonline/RnClient.exe`, SHA256 `cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77`.

- First construction sender7BC3D0:0037/6 bytes; response661F50:403D/5-byte consumed prefix, local6073, phase6. See `protocol-analysis/richonline-rebuild/game/startup-flow/construction216/findings.md`.
- Upgrade sender7BC480:0038/6 bytes; response662280:403E/5-byte consumed prefix, local6070->680490->7E3F30, phase7. See adjacent `upgrade-findings.md`.
- First construction and upgrade responses have different phase handling. No upgrade cash/deposit/licence debit is present in the NEW path. BS_1_1 default kind11 and scenario/BOSS caps derive from Build/BossWar resources; human caps come from the same participant skills sent in board initialization.
- Synthetic deterministic acceptance follows the user's requested behavior. Deadline cancellation is server policy using the confirmed cancel responses, not a claim about historical server timeout logic.

## Verification

Before production changes, the new case in `richonline_boss_property_tests.cpp` failed with `FAIL owned_boss_property_did_not_build_and_resume`. After the repair the same case passes.

Full isolated CMake build with project strict warnings passed. Full CTest:96/96 passed,28.20 seconds. Logs: `native-server/build-owned-property-20261009/evidence/full-build.log` and `full-tests.log`.

Nine actual encrypted TCP scenarios use ephemeral sockets, real GameService, admission/envelope codecs and the production turn/property handlers: BOSS building levels0/1/5; human first-build/upgrade each with accept/cancel/timeout. They verify no premature response while waiting, exact4013/403D/403E ordering, next actor's turn, late replay followed by a valid subsequent movement, unchanged owner/cash, and exactly one level mutation. Unit cases additionally cover shared land, skill/scenario cap differences, default confirmation, missing/disabled licences, exact consumption, expiry boundary and duplicate rejection.

Independent IDA investigator reviewed final own-property code and found no blocking issues. LSP verification was unavailable because the OMO LSP daemon could not be reached; no clean-LSP claim is made. Native client UI testing remains with the user; no computer-use, live account mutation or server restart was performed.

## Candidate and integration scope

Candidate: `native-server/build-owned-property-20261009/evidence/RichOnline.Server.owned-property.exe`.
SHA256:`E51840E3A4BD1CF0B66443F281CFBF63284213ACAF2823DE37B1102437700CC2`.

The repair is in the shared source, including CMake integration. The independent candidate was not substituted into the manager's launch configuration because another active chat is integrating additional server work. Native UI acceptance and deployment of the combined build remain outstanding. Opponent-owned property effects, actor collisions, other map families and persistent inventory consumption are outside this repair's verified scope.
