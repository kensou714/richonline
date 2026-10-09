# Vendored native dependencies

Downloaded 2026-10-09 from official upstream endpoints. No upstream application code copied.

- SQLite 3.50.4 amalgamation: https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip
  - Archive SHA-256: `1d3049dd0f830a025a53105fc79fd2ab9431aea99e137809d064d8ee8356b032`
  - Upstream public domain dedication is retained in sqlite3.c/sqlite3.h; shell.c is not built.
- nlohmann/json 3.12.0 single header: GitHub contents API of `nlohmann/json`, ref `v3.12.0`.
  - Header SHA-256: `0d55a51a8ad7a9e3ff129639c29d23eea480242aa1d855d4f4d47e629555dbd2`
  - MIT license retained at `nlohmann/LICENSE.MIT`.
- Lua 5.4.8 is still pinned and verified by the existing CMake FetchContent declaration.

This build does not execute Python. Existing historical Python test harnesses are separate comparison artifacts, not runtime requirements.
