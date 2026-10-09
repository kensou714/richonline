# C++ auxiliary service evidence

Scope: C++ WinSock HTTP bootstrap and the read-only empty blacklist list operation. Verified on native Windows 2026-10-09. This does not certify login, lobby callbacks, or BOSS playability.

## Source and field provenance

- New-client source schema: `protocol-analysis/richonline-rebuild/auxiliary/protocol.json` and its `raw/` directory.
- HTTP: `0x69EEE0` and `0x69F750` read the `area` / `area0` / `channel0_0` grammar and the emitted field names. The server generates the document from the configured advertised IPv4 address, lobby port, capacity, channel ID, and live player-count callback. ASCII `Local` is the configured local lobby label. `LobbyStatus=1`, gold limits 0..999999999, and level limits 0..999 are current explicit local channel policy; their complete business domains remain unproven. Optional `LobbyType` is omitted, so the new client's documented default path applies. No client resource file or arbitrary URL-derived disk path is read.
- Black response: `0x858FB0` verifies CRLF plus type and an exact payload length from `0xA2F7D0`. Type 0 requires 33 bytes. The `name[0] == 0` path invokes callback `(0, 0)` before reading the flag. Therefore a 32-byte zero name plus one zero byte is an exact list terminator. Other name bytes and the flag are unused on this branch, not claims about an unknown flag's meaning.
- The native auxiliary service has no stored blacklist entries and no mutation implementation, so its list is actually empty. It does not claim to validate the opaque auxiliary authentication transform. The response event explicitly carries reason `empty_blacklist_terminator_auth_not_asserted`. Non-list operations close with `black_operation_not_implemented` rather than fabricated status codes.
- Inquiry and Intro are not opened. Current migrated accounts mean a fabricated empty ranking would be false, and the profile text data source has not been connected. The saved schema remains the required evidence for subsequent real data-backed implementations.

## Build and observed TCP behavior

Build, exit 0 with no warnings:

```bash
clang++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion -Iinclude src/auxiliary_service.cpp src/auxiliary_protocol.cpp src/frame.cpp tests/auxiliary_tests.cpp -lws2_32 -static -o build-ninja/auxiliary-agent-tests.exe
```

Observed command:

```text
./build-ninja/auxiliary-agent-tests.exe
auxiliary real TCP tests PASS (7 scenarios)
exit 0
```

The test starts actual listeners on ephemeral loopback ports and sends/receives through actual TCP client sockets:

1. Both exact HTTP routes, byte-fragmented requests, correct Content-Length, configured address/port/capacity and live player count.
2. Unknown disk-like paths return 404 and POST returns 405.
3. Fragmented blacklist list request receives the exact 43-byte framed terminator.
4. An ADD request receives no fake success and records the exact unsupported-operation reason.
5. Wrong blacklist payload length closes and records the exact invalid-length reason.
6. An 8193-byte HTTP header exceeds the 8192-byte limit and receives no response.
7. `stop()` and thread join close accepted idle clients and release both listeners.

The first lifecycle test failed with WinSock error 10093. The test client incorrectly relied on the server's initialization reference. Adding a separately owned client WinSock runtime fixed the test fixture; production server behavior was not weakened to hide the failure.

Runtime limits: 32 peers, 8192 HTTP request bytes, 106 blacklist request bytes, five-second request deadline, two-second send timeout, 100 ms select observation interval. Socket ownership is RAII; the caller owns and joins the run thread. Default bind address is loopback. No request names, auth slots, or raw URLs are logged.

Measured pure LOC: public interface 38, internal response interface 8, protocol 66, service loop 140, TCP tests 216. Protocol parsing remains at the boundary; structured event callbacks supply service kind, connection ID, wire type, byte lengths and stable reason codes to the main server's existing logger.
