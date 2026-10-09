# Native administrator control v1

The C++ service is the only SQLite writer. The .NET administrator never writes SQL.
Experimental native builds explicitly return `gameReady:false` until real game listeners and gameplay are integrated.

## Launch

`RichOnline.Server.exe --data-dir ABSOLUTE_DIRECTORY --pipe PIPE_NAME`

The service creates its data directory and owns a lifetime lock there. The pipe name contains only ASCII letters, digits, `-`, `_`, `.`, max 80 characters; callers pass the name, not a full Win32 path. Pipe ACL allows the process user and rejects remote clients. GUI uses a fresh name per launch. Default native data directory is `native-data` beside the GUI, never the existing Python database.

`RichOnline.Server.exe --import-db SOURCE --data-dir EMPTY_TARGET_DIRECTORY` creates an SQLite backup in the new directory without changing the source. It is an explicit offline setup operation, not an automatic import on normal startup.

## Framing

One request and one response per pipe connection. Four-byte unsigned little-endian byte length followed by UTF-8 JSON. Length must be 1..65536 before allocation. Client timeout 5 seconds. IDs are nonempty strings of max 128 characters. No request body is copied to logs.

Request: `{"version":1,"requestId":"...","command":"status","payload":{}}`

Success: `{"version":1,"requestId":"...","ok":true,"result":{...}}`

Failure: `{"version":1,"requestId":"...","ok":false,"error":{"code":"stable_code","message":"diagnostic"}}`

## Commands

- `status`: `{pid,instanceId,protocolVersion:1,dataDirectory,gameReady:false,state:"running",capabilities:[...]}`.
- `stop`: `{stopping:true}`; flush response then stop and exit.
- `accounts.list`: payload `{offset:0,limit:100}`; result `{accounts:[{role_id,username,name,model,level,experience,coins,gold,bank,...}],total}`. Never returns hash/salt/password.
- `accounts.create`: `{username,password}`; result public account/role. No automatic reset of existing account.
- `accounts.update`: `{role_id,expected:{...loaded account...},changes:{...changed public fields...},reason:"..."}`. Atomic compare/update/audit; stale edits return error.
- `config.get`: `{settings:{...},revision:integer}`.
- `config.update`: `{expectedRevision:integer,settings:{...}}`; validates configuration and compares revision. Stored settings do not imply unimplemented game features are active.
- `database.backup`: `{}`; result `{path}` of service-chosen backup under the data directory.

## stdout and log file

UTF-8 JSON lines: `{timestamp:"UTC ISO8601",level:"info|warning|error",event:"...",...event-specific fields}`. Initial `ready` includes pid, instanceId, pipe, protocolVersion, dataDirectory, gameReady. Only after receiving ready and matching status PID may the GUI show the management service running. The game readiness is displayed separately.

GUI consumes stdout/stderr asynchronously, keeps bounded visible rows, permits copying errors and opens the persistent log directory. Any malformed/unstructured stderr is shown verbatim as an error, never silently discarded. Command failures include the command and stable code but no payload.
