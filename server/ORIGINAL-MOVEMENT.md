# Original native movement

This C++20 library targets root RnClient.exe. Evidence is in
`protocol-analysis/ORIGINAL-MOVEMENT-RECHECK-20261009.md`; it is not evidence for
the separate Richonline client. No Python runtime or generated resource export
is needed. Production original room handoff and full BOSS strategy remain
unconnected, so this module does not enable `gameReady`.

## Contracts and fields

`original_movement_wire` parses exact C2S16/17/18/20/52 lengths. Context is the
low16 turn counter; it is distinct from the S2C GmsvID. C2S20/52 trailing bytes
are preserved opaque values. Nonzero roll parameters remain unresolved and
are rejected by the ordinary-roll strategy boundary.

4011 writes all28 observed bytes: GmsvID, starting tile, dice count, direction
count, three face bytes,13 explicit storage bytes and signed-range gold-bean
charge. Only used two-bit direction pairs overwrite caller storage. Regular
rolls require1..3 dice, active faces1..6 and1..36 directions. Unused face0
is an explicit inactive-die value; charge0 means a free roll. The four bytes
at20..23 have no recovered business meaning and are not silently zeroed.
4013 and4035 carry their proven fields plus explicitly supplied suffixes.
The tests' nonzero opaque storage is a fixture, not a claimed original-server
constant.

`original_route` uses the original immutable EMP model and a per-roll dynamic
object snapshot. It honors chosen first direction, otherwise the available
current heading; later forks use an injected nonreverse random policy.
That policy is local server behavior, not recovered original server RNG.
Object29 reverses before entry;11 stops and30 extends once per tile, up to18
additional steps. Mines12/27 remain for landing processing. Type61 portal
relocation occurs between encoded steps and does not consume a direction.
The owning strategy supplies portal pairs/control gates. Reconstruction
checks physical edges and dice-sum/extension/stopper budget independently.

## State ownership

One `OriginalMovement` belongs to one moving actor. The caller supplies the
instance, context, map, position, heading, dice preference and wire policy.
Update effects while ready, then issue a roll. Only the exact predicted normal
endpoint may report17. An18 needs a predicted timed-bomb explosion at its
specific step; route membership is insufficient. Invalid reports leave the
issued movement intact. Dice preference changes update the next roll without
discarding a current route or pending landing decision.

An accepted17 emits4013 and enters `landing`; the returned event includes
the real road cell and consumed11/30 objects. The battle strategy resolves
shop/property/card/god/mine work, calls `wait_for_direction` if appropriate,
and only then calls `finish_landing`. A fork52 emits4035 and preserves its
chosen heading for the next roll. Cancellation preserves current heading;
if no road continues in that direction, normal route choice selects a valid
nonreverse edge. `allow_direction_choice` must exclude AI, relevant control
states and special-game states, using the recovered client gates.

An accepted18 enters `interrupted`, consumes any reached11/30 and returns the
predicted bomb roster, transfers and expired owner byte. It emits no fabricated
4015 and does not resume the remaining route. Damage, relocation, animations,
survival and next-turn sequencing belong to a future battle resolution policy,
which must explicitly call `finish_interruption` after completing them.

## Timed bombs

`OriginalBombRoster` holds the mover's attached bomb and other actors' snapshot
positions, active flags and raw signed status1493/status1489. Their business
labels and the owner byte's domain remain unresolved; values are preserved.
An empty roster explicitly means no bombs/other participants for this movement;
production multiplayer must supply the entire authoritative eligible roster.

Each entered edge decrements the mover's bomb, stopping immediately at zero.
Otherwise, an armed mover swaps count/owner with the lowest eligible slot at
that tile. Both target statuses must equal-1 and the target must be active.
An unarmed mover cannot collect another actor's bomb. A received countdown
starts decrementing on the next physical step, not the transfer step. Special
game state disables countdown, but does not disable transfer. Implicit portal
relocation does not decrement. Prediction does not mutate the input world;
results become movement state only after an accepted report.

The owning battle loop must serialize actor movement/world updates, authenticate
the reporting session, and reconcile identical observer reports. This class
is not a multiplayer acknowledgement barrier. Separate4009/event14 recovery
reports, intermediate40/42 events, complete landing handlers, timeout policy,
combat effects and production Lua turn integration remain explicit work.

## Verification

New wire, route, movement, bomb and encrypted-TCP suites cover exact bytes,
opaque preservation, malformed/context/replay rejection, four original BOSS
maps, dead ends,29/11/30, mines, portals, bomb swaps/expiry/slot filters,
special-game transfer and explicit completion. The real GameService scenario
loads BS_1_1 and drives179→178,52(direction2), then178→162. Startup/envelope
unknowns and completion of the shop tile are explicitly synthetic fixtures;
this is not full client gameplay acceptance.
