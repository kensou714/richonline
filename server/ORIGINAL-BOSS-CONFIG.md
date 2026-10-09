# Original client BOSS stage policy

`OriginalBossConfig` reads the existing `local-server/boss-stages.json` directly in C++.
`parse(text, known_card_ids)` and `load(path, known_card_ids)` require a caller-supplied
set of enabled original-client CARD identifiers. There is no guessed identifier range.
`stages()` retains all metadata and nullable settings; `playable(stage_id)` returns
required typed values by value and rejects unknown or disabled stages.

All 18 schema fields, including attack policy, must be explicitly present. Unlike the
old Python reader, the native reader does not inject attack defaults. Existing checked-in
data already supplies every field. Extra fields, duplicate JSON keys, duplicate stage
IDs, invalid types, excessive nesting, and documents over 1 MiB are rejected. Stage IDs
are canonical `BS_<positive integer>_<positive integer>` and map names must equal the
stage ID plus `.emp`. The existing support declaration is restricted to `BS_1_1` through
`BS_1_4`; this is migration policy, not proof that gameplay is implemented natively.

Balances and tickets are explicit nonnegative signed-32-bit amounts. Human initial
cards retain their order and may repeat, with at most eight inventory entries. Human
building skills are explicit 0..7. Disabled stages may retain null settings; they can
never be selected through `playable`, even if all values are populated.

Attack policy is local gameplay policy: 0..8 attempts, each probability weight 0..100
and all three weights summing to 100. The weapon pool is nonempty, unique, and restricted
to the currently implemented missile/nuclear/safe-nuclear actions (1046, 1063, 1075),
which must also belong to the supplied enabled-card set. This parser does not encode
network packets or infer unresolved packet fields.

The tests use the five identifiers needed by the real configuration, independently
confirmed as `type = CARD`, `enable = true` in original
`protocol-analysis/boss-combat/Prop.txt`: 1038 (line 2007), 1044 (2224), 1046 (2294),
1063 (2909), and 1075 (3341). Other enabled IDs are accepted for human inventory when
supplied by the caller. Tests read the real stage JSON plus independent nondefault
fixtures and malformed schema, range, card, disabled-stage, and document boundaries.
