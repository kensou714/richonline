# Native client profiles

`RichOnline.Server.exe --data-dir <absolute-directory> --pipe <name> --client-profile original`
selects CP936 (GBK) for UTF-8 account/password input from the control API and role-name validation.
`--client-profile richonline` remains the default and selects CP950 (Big5). The password verifier
always authenticates the exact password bytes received from the game client; opening a database
does not convert, reset, or rehash any existing account.

Both the `ready` event and the `status` result contain `clientProfile` (`original` or `richonline`).
This identifies the encoding contract, not gameplay readiness; `gameReady` remains false.

Fresh databases record `metadata.client_profile`. Reopening a tagged database with a different
profile fails with `database_client_profile_mismatch`, even if adoption was requested.

An existing untagged database has no reliable encoding provenance. Opening it fails with
`database_client_profile_adoption_required` until the operator explicitly asserts its profile:

```text
RichOnline.Server.exe --data-dir <absolute-directory> --pipe <name> --client-profile original --adopt-client-profile original
```

Use `richonline` in both arguments only for a database whose account passwords were created
from Big5 bytes. Adoption only records that assertion; it cannot convert passwords whose
original plaintext is unavailable. A mismatched pair of options is rejected. Copying with
`--import-db` preserves the source database and its profile metadata exactly; import never
guesses or stamps a profile, and cannot be combined with adoption. Adopt an untagged imported
copy on its later startup after confirming its provenance. The GUI must not silently adopt
old data directories. Use a fresh directory for a new original-client deployment.
