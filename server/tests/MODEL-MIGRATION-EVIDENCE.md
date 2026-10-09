# Model domain migration evidence

The native C++ storage migration upgrades Richonline databases from schema v5 to v6, expanding only the `roles.model` CHECK domain from 0..4 to 0..8. Original-client databases remain v5 with a 0..4 domain. The administrator role/default validation uses the same client profile limit.

## Safety boundary

- The service owns a `BEGIN IMMEDIATE` transaction before migrating, preventing competing database writers during its snapshot and schema change.
- Existing databases first receive a full SQLite backup under `backups/before-model-v6-*.sqlite3`. An independent read-only connection captures the committed pre-transaction state. A failed backup prevents migration.
- Table reconstruction preserves the original DDL apart from the model CHECK, all nongenerated column values, generated column definitions, indexes, triggers, views, foreign key targets, and an AUTOINCREMENT sequence when present. Unsupported model declaration shapes fail closed.
- Foreign keys are disabled only on the private initialization connection for reconstruction. Foreign-key and integrity checks run before and after the rebuild; normal operation re-enables foreign keys after commit.
- Version update, profile adoption, reconstruction and bootstrap changes share one transaction. Failure rolls these changes back; the pre-migration backup remains available.
- Import still opens the source read-only and requires a new destination path. Normal construction of an imported, untagged legacy database requires explicit client-profile adoption.

## Observed legacy deployment schema

On 2026-10-09, a standalone native helper opened `Richonline/native-data/richonline.sqlite3` with `SQLITE_OPEN_READONLY`. It queried only the roles CREATE TABLE statement and metadata keys `schema_version` / `client_profile`; it did not construct Storage or migrate the deployment database.

The table matched the older Python-generated schema shape: STRICT table, unquoted roles/model identifiers, `model INTEGER NOT NULL CHECK(model BETWEEN 0 AND 4)`, finite REAL upper bounds, and fields appended by earlier migrations. Both the CREATE TABLE recognizer and exactly one model-domain recognizer matched. Metadata reported schema v5 and no client-profile tag. This requires explicit adoption before any future native opening. No production migration was performed.

## Isolated validation

`tests/model_migration_tests.cpp` runs against newly created fixture databases only. The latest standalone strict Clang build uses `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion`.

Covered boundaries:

- Nine Richonline character IDs through selection, administrator editing, and new-account defaults; original character limit remains unchanged.
- Exact preserved role values and REAL balances, an unknown extension BLOB table, a generated column, partial index, custom trigger, view, foreign keys, operations and audit records.
- SQL engine directly rejects model 9 and foreign-key violations; the saved v5 backup still rejects model 5.
- SQL compares preexisting account verifier and preference values with the backup and returns only the mismatch count, never credential materials.
- Failure injected at the final schema-version update rolls back the already reconstructed table and dependent objects. Retry succeeds after removing the fixture-only fault.
- Failed backup directory creation prevents migration; AUTOINCREMENT high-water marks survive reconstruction.
- The observed legacy Python DDL shape migrates with explicit profile adoption while retaining its finite-balance CHECK constraints.

Standalone artifacts are retained under `native-server/model-migration-<pid>-<timestamp>/`. The parent integration task owns the final CMake/CTest build record.
