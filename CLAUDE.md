# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

```bash
# Debug (includes clangd compile_commands.json)
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build

# Release
cmake -B build-release -DCMAKE_BUILD_TYPE=Release && cmake --build build-release

# Without TLS
cmake -B build -DENABLE_TLS=OFF && cmake --build build

# Without examples
cmake -B build -DBUILD_EXAMPLES=OFF && cmake --build build
```

Build dir: `./build/`. Dependencies (shift, shift-io, nghttp2) fetched automatically via FetchContent.

## Testing

No unit test framework. Smoke-test via examples:

```bash
# Server: h2c echo (cleartext)
build/examples/h2c_echo 1

# Client against it
build/examples/h2c_client 127.0.0.1 9000 /path

# Load test (requires h2load from nghttp2-tools)
./scripts/load_test.sh quick|moderate|heavy|sustained
```

## Architecture

C23 HTTP/2 library built on three layers:
- **shift** — ECS framework (entities, components, collections)
- **shift-io** — io_uring async I/O (accept, read, write, connect)
- **nghttp2** — HTTP/2 wire protocol

### Setup pattern

1. `shift_context_create()` — create ECS context
2. `sh2_register_components()` — register all sh2 component types
3. User registers collections with required components via `shift_collection_register()`
4. `sh2_context_create()` — create h2 context, passing user collections in config

The user owns all API-boundary collections (principle 11). sh2 creates internal pipeline collections as archetype supersets.

### Poll loop (sh2_poll.c)

Each `sh2_poll()` call runs a multi-phase pipeline with `shift_flush()` between phases:

1. Consume user input (responses, connect/disconnect/cancel requests)
2. Initialize new client connections, process connect errors
3. Triage read results by connection state → route to init/handshake/active/error collections
4. Handle read errors, init new connections, drive TLS handshakes
5. Feed active data to nghttp2
6. Account for completed writes, finalize draining connections
7. Drive all nghttp2 output (submit writes to sio)

### Connection state machine

State is collection membership (never flags). Connection entities move between:

`sio_connections (NEW)` → `coll_conn_tls_handshake` (if TLS) → `coll_conn_active` → `coll_conn_draining` → destroyed

Read entities are triaged into separate collections by connection state and direction (server vs client).

### Entity flows

**Server:** `request_out` → app processing → `response_in` → `response_sending` (internal) → `response_out` → app destroys

**Client connect:** `connect_in` → sio pipeline → `connect_out` (success, session set) or `connect_errors` (failure, io_result set). Same entity throughout (principle 8).

**Client request:** `request_in` → `client_request_sending` (internal) → `response_out` → app destroys

### Key internal types

- `sh2_conn_t` — per-connection state (nghttp2 session, TLS, pending writes, direction). Lives as `internal_conn` component on the connection entity itself.
- `sh2_stream_t` — per-stream header/body accumulation. Stored as nghttp2 stream user_data, not a shift component.
- `sh2_ng_ctx` — nghttp2 session user_data wrapper linking back to sh2_context + connection entity.

### Memory ownership

| Data | Allocated by | Freed by |
|------|-------------|----------|
| `req_headers.fields`, `req_body.data` | sh2 | sh2 component destructor |
| `resp_headers.fields`, `resp_body.data` | App (malloc) | sh2 component destructor |
| `resp_headers` name/value pointers | App | NOT freed (may be literals) |
| `peer_cert` strings | sh2 | sh2 component destructor |

### Client-only mode

Set `client_only=true` in config. Server collections not required, no listener, no server nghttp2 callbacks. Requires `enable_connect=true`.

### Design principles

See `~/.claude/memory/shift-library.md` for the full set. Key ones for this codebase:
- **State is collection membership** — no enum flags for entity state
- **Entity identity spans the lifecycle** — never destroy user entities and create replacements
- **Libraries are component-transparent** — internal collections are archetype supersets
- **Pass input components through to output** — output archetypes include input components by default
