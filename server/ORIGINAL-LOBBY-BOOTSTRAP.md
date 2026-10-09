# Original RnClient lobby bootstrap

The original client runtime reads `lobby-bootstrap.json` from its explicit original-profile data directory. This schema is separate from the Richonline client schema: the original room record is 220 bytes and the original profile record is 268 bytes. An original SQLite database and `--client-profile original` are required. No profile conversion or packet-template defaults are supplied.

The following shows the schema, not a runnable packet fixture. Replace each angle-bracketed template with a full hex string from evidence for the original `RnClient.exe`, and document that evidence in `provenance`. Do not fill unknown bytes with zeroes to make this example load. The example's policy choices are illustrative, not original-server captures.

```json
{
  "version": 1,
  "client_profile": "original",
  "provenance": "<original-client evidence source, capture or reconstruction details>",
  "network": {
    "bind_host": "127.0.0.1", "lobby_port": 7000,
    "auxiliary": { "advertised_host": "127.0.0.1", "http_port": 7080, "black_port": 7004 }
  },
  "room_template_hex": "<220 bytes / 440 hex characters>",
  "role_template_hex": "<208 bytes / 416 hex characters>",
  "profile_template_hex": "<268 bytes / 536 hex characters>",
  "login_template_hex": "<16 bytes / 32 hex characters>",
  "identity_template_hex": "<16 bytes / 32 hex characters>",
  "bank_template_hex": "<32 bytes / 64 hex characters>",
  "completion_template_hex": "<28 bytes / 56 hex characters>",
  "room_id": 3,
  "game_capacity": 8,
  "player_capacity": 100,
  "item_grid_count": 32,
  "item_per_space": 2,
  "stage_progress_hex": "01020300",
  "setting_text": "12",
  "tutorial_dismissal_mask": 14,
  "client_options_path": "../Data/Option.kpd",
  "map_catalog_path": "../protocol-analysis/board-startup/maps/index.json"
}
```

All original 19 top-level fields are mandatory; `client_options_path` and `map_catalog_path` are optional and all other unknown fields are rejected. The policy loader requires a `network` object; the runtime separately validates its bind address and lobby port before opening a listener. All numeric fields must be JSON integers, not booleans, strings or fractional numbers. Files must be nonempty and at most 64 KiB. Hex strings contain only paired `0-9`, `a-f` or `A-F` characters, with no spaces or `0x` prefix.

| Field | Contract |
| --- | --- |
| `version`, `client_profile` | Exactly integer `1` and string `original` |
| `provenance` | String of at least eight bytes identifying the original evidence |
| Seven `*_template_hex` fields | Exact sizes above; bytes are preserved until proven adapter fields are replaced |
| `room_id` | Integer 1..32766 |
| `game_capacity`, `player_capacity` | Integers 1..32767 and 2..32767 respectively; these are index capacities, and every emitted role ID must be less than player_capacity |
| `item_grid_count`, `item_per_space` | Integers 1..65535 |
| `stage_progress_hex` | 1..4096 decoded bytes, final NUL and no earlier NUL; S2C103 binary stage progress, not text announcements |
| `setting_text` | 1..10 decimal characters, value at most 2147483647; leading zeroes retained by loader |
| `tutorial_dismissal_mask` | Integer 0..2147483647; ORed into S2C106 preferences without mutating stored account preference |
| `client_options_path` | Optional UTF-8 path to the original `Option.kpd`; relative paths resolve beside this bootstrap. C++ reads `[J_R] ratio`; missing/corrupt/ambiguous configured files fail startup, never fall back to a guessed ratio |
| `map_catalog_path` | Optional UTF-8 path to the original extracted map index; relative paths resolve beside this bootstrap. Missing/corrupt configured catalogs fail startup. Omission leaves room creation/configuration unavailable |

The adapter replaces only documented fields in the templates. The fixed 220-byte room response explicitly writes extension length +212 as zero (no appended bytes), and serialized pointer slot +216 as zero (the client decoder relocates it). These are defined empty-extension values, not unknown-field filler. The bank template's +8/+16/+24 doubles are minimum deposit, minimum withdrawal and capacity; finite/nonnegative limits are validated and minima cannot exceed capacity. Bank+0 bytes and unknown completion bytes remain preserved. Template acceptance is structural validation, not proof of historical protocol correctness.

The optional `network.auxiliary` object enables original HTTP discovery and blacklist listeners. It requires all three fields shown; ports are integers 0..65535 (zero allocates an isolated test port). Omit the entire object to run only the original lobby. Unknown network or auxiliary fields are rejected. Discovery serves both original gameinfo text routes with the actual bound lobby port, current authenticated session count, policy capacity/room ID, and LobbyType=0 (the local ordinary-lobby policy). These routes are confirmed in original `local-server/config_tools.py`, not inferred from the other client. Configured ports must match the client region file for an actual client run.

Blacklist state uses `original-blacklist.sqlite3` beside the bootstrap file, keyed by raw role nickname and MD5 of the raw login account name. This is an identity namespace, not password authentication. Modes 0/1/2 persist list/add/remove; mode4 persists the enabled flag. A successful mode4 deliberately sends no S2C frame and closes normally, matching the observed optimistic local UI update and connection queue's FIN handling; the historical server response remains unknown. Mode3 request semantics remain unverified and are explicitly rejected. See `protocol-analysis/ORIGINAL-BLACK-FIELDS-20261009.md` for original-only evidence.

The original path also supports authentication, role catalog, role selection bootstrap, preference persistence and native gold bank transactions. When `client_options_path` is supplied, M-point exchange C2S42 uses the original file's ratio and sends S2C79 followed by the committed full S2C23 profile. Without the file setting, exchange explicitly rejects as unconfigured. Option changes take effect on service restart. Stage/mall lists do not establish mall shopping or game support. `gameReady` stays false; `httpReady`/`blackReady` report their configured listeners independently. Original-client gameplay and UI queue acceptance have not been demonstrated by the synthetic TCP tests.
