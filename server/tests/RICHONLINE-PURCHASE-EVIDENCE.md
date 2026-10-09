# New-client property216 purchase continuation

Target client: `Richonline/RnClient.exe`, SHA256 `cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77`.

## Contract and supported scope

Source contract: `protocol-analysis/richonline-rebuild/game/startup-flow/human-property/` (104 raw IDA artifacts, contract and independent scoped review). The initial BS_1_1 property216 at231/232 has price100, owner-1 and degree2. Only empty-status mode3 landings without another actor are supported. Human cash must be strictly greater than100 to open a purchase decision; insufficient or equal cash completes locally after4013 without4020.

C2S0x20 is12 bytes: opcode u16, calendar low16, secondary u32 (ordinary audited UI value0), accept u8 (0/1), and three unconsumed bytes preserved by the codec. It contains no property, price or actor; those come from the pending server decision. S2C4020 uses the audited five-byte consumed prefix with GmsvID and decision. Historical full size is unknown.

Acceptance applies the cash debit and ownership once, then emits4020(1) before next4010. Decline emits4020(0) without a debit. Ordinary client UI timeout does not send a decline. The local server policy therefore rejects the pending purchase after E88+56 seconds, using a steady clock starting at the accepted movement completion. This interval matches the UI configuration; the original server's deadline policy and animation scheduling are not recovered. A click at or beyond the deadline is also declined.

The game startup layer exposes optional poll and a business-validated retired-action callback. Only a correctly encoded0x20 carrying the most recently completed purchase's calendar can be ignored as a late request. Other stale counters still fail. This prevents a delayed click after a timeout from charging the next actor or disconnecting a valid session. Map-not-ready and disconnected games never invoke business polling.

## Verification so far

- New domain methods first failed at link with undefined enable_human_decisions/decide/poll; implemented methods then passed property and wire tests2/2.
- Turn integration first failed `property_turn_poll_missing`; after wiring, card-turn/runtime tests2/2 passed.
- Startup poll and retired-action tests were independently red then green. They verify counter updates through ordinary output validation, invalid instance rejection, no callback before map load or after release, and no global stale-opcode exemption.
- Real encrypted TCP purchase tests passed: timeout at5000ms sends4020(0), manual acceptance sends4020(1), late/duplicate request does not debit again or disconnect, and BOSS234 completes before the next human turn. Cash/owner assertions happen after joining the service thread.
- The shifted233 human-spawn TCP scenario uses the actual resource builder and production GameService/startup/turn/property handlers with an explicit test spawn. It is not a production-host spawn test. The host correctly rejects changing its initialization snapshot. The discovered host/registry poll-forwarding gap is now fixed. Separate host/registry tests cover forwarding only after map-ready, admission matching, cancelled entries, gate-serialized cancellation and exactly-once cleanup.
- Latest full build passes. Full CTest83/84 in6.13 seconds: every new-client test passes. Concurrently added `native_original_boss_match_tcp` fails with `original_boss_match_tile_unimplemented type=70 tile=121`, then `reply_missing`; this original-profile implementation was not modified here. Do not report the full suite as green.

## Deployment

Pinned server `local-server/runtime/native-boss-live-20261009/RichOnline.Server.purchase.exe`, SHA256 `18a4e4290b4dcf47725fc2a83fdfe85789f7738e8adef88a62e8cd14c67dd0f3`, is running as44128 / instance44128-265984238135000. Lobby18600, game18602, blacklist18604 and HTTP18680 report ready. `gameReady=false` and authenticatedSessions0 remain explicit. Startup stderr is empty. Before switching, an online backup `accounts-1791498428852184.sqlite3` was retained and idle38160 was stopped via instance-checked control request. Its binary remains intact for recovery.

The self-contained .NET manager passed9 actual control-interface checks against the pinned purchase EXE for each profile (richonline and original). Results are archived in `native-purchase-admin-check-richonline-20261009/control-test-result.json` and `native-purchase-admin-check-original-20261009/control-test-result.json` under `local-server/runtime`. These cover account creation/edit/CAS conflicts, config revision conflicts, SQLite backup, graceful stop, profile selection and client KPD staging. Test accounts are isolated from live data. An initial result lookup followed an incorrect README statement: the harness writes next to its EXE, not inside the test data directory. README is corrected. An older framework-dependent binary rejects the profile parameter; it is not the validated package. No actual GUI clicking is claimed.

## Limits

No actual native client purchase interaction was observed. Later owned-property construction/rent, discounts/statuses, all other properties and full match completion remain separate work. IDA proves that BOSS-owned216 revisit at level0 requires a construction response (403D), so this implementation does not treat it as empty land.
