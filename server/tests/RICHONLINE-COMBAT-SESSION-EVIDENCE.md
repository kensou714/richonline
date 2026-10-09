# Shared combat coordinator verification

Scope: `richonline_combat_session.hpp`, `gameplay/combat_session.cpp`, and the standalone coordinator tests. No session, turns, CMake, live process, account, or client state was modified by this work.

## Contract

The coordinator receives a snapshot of authoritative actor status, inventory, funds, dynamic NPCs, mines and normalized properties. Preparation mutates only `plan.after`. The result contains exact attack packets, coalesced per-actor funds updates, sequential prepared helmet consumptions and actor IDs newly bankrupt. It does not broadcast, debit persistent accounts, settle a match or own a duplicate status store.

`commit_richonline_combat_plan` requires a caller-supplied atomic adapter. Under session serialization, the adapter compares the global revision and all source snapshots, validates all card/property updates before mutation, and uses the shared funds ledger's `commit_batch` for funds CAS. The callback must leave every store unchanged on false or throw. Only successful commit permits broadcast and bankruptcy settlement. An optimistic global revision alone is insufficient if owner modules mutate without incrementing it. The coordinator's public snapshots do not substitute for authorization at this boundary.

The world adapter supplies legal visible target tiles after each preceding action, cardinal walkable topology, shared helmet activation and normalized building update rules. Uniform bounded RNG is invoked after the legal set is known, avoiding modulo bias and stale indices. A stage explicitly chooses its projectile mix. Default is missile; no unproven nuclear mixture is silently introduced.

Four independent draws implement 80% no attack, 10% mine, 10% configured projectile. Self tiles remain eligible. Attacks never consume the BOSS hand. Sleepwalking, freezing, hospital, prison or elimination prevent attacks. A blast resolves all simultaneous victims against its attack-time snapshot; later attacks observe committed-to-plan damage, consumed helmets and destroyed map objects.

Mine clock packets are ordered `401E` then one `4017` for each still-existing expired connected component. Tracing retains expired roots until graph resolution; fresh mines reached by the chain detonate too. Stepped and projectile-triggered chains emit no extra `4017`, since the client already queues those animations. Each overlapping mine retains its own owner multiplier; damage sum receives the normal-mine overlap bonus. Last-day rendering follows the existing one-day remaining timer. Current representation is normal NPC12 mines only, not NPC27 super mines or timed-bomb attachments.

Projectile rules and damage facts are backed by `protocol-analysis/richonline-rebuild/game/combat-new/NUCLEAR-AND-MODIFIERS.md`. The session must supply current resolved equipment/building/special modifiers, and suppress mine-day entry while client `game+83830 != -1`; this coordinator does not infer that separate mode from actor status. Its building rules apply to the BOSS/PK branch, not normal-mode nuclear property damage. Building adapter owns level-zero small/large building normalization and production effects. Settlement packet ordering and final win conditions remain the owner module's responsibility.

## Executed validation

From `native-server`:

```text
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion -I include tests/richonline_combat_session_tests.cpp src/gameplay/combat_session.cpp src/gameplay/combat.cpp src/gameplay/ledger.cpp src/frame.cpp -o tests/richonline_combat_session_tests.agent.exe
tests\richonline_combat_session_tests.agent.exe
```

Both exit 0. Output: `richonline combat session tests passed`.

Tests exercise probability thresholds; visible tile selection and changing target bounds; self damage and all footprint victims; cumulative attacks and coalesced funds revisions; self-bankruptcy stopping subsequent attacks; controlled actors; untouched prepare snapshots; noninventory actor presentation; three mine days and red final day; duplicate/gap days; connected expiring roots with one animation; fresh neighbor chain detonation; distinct owner attack modifiers and overlap bonus; vehicle mine immunity; stepped/projectile chain without duplicate wire; helmet consumed exactly once; normalized 2x2 property effects; nuclear versus missile building rules; safe nuclear self exclusion; missing property adapter rejection; bounded RNG validation; actual shared ledger CAS success; stale global/ledger revision rejection; false/throw retry semantics; duplicate commit rejection.

The transaction fixture prepares all potentially allocating map work before the ledger callback, then swaps a prebuilt snapshot under the callback. A stale ledger revision is verified to leave the other actor and map untouched. This verifies the adapter pattern, not a production session integration. No computer-use or live client test was performed.
