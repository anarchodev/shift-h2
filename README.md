# shift-h2

HTTP/2 server and client library for C, built on the [shift](https://github.com/anarchodev/shift) ECS framework, [shift-io](https://github.com/anarchodev/shift-io) (io_uring async I/O), and [nghttp2](https://github.com/nghttp2/nghttp2). Optional TLS support via OpenSSL, including mutual TLS (mTLS) and SNI-based multi-tenant certificate selection.

HTTP/2 requests and responses are modeled as ECS entities with typed components, flowing through collections that represent processing stages.

## Features

- **Server**: Accept HTTP/2 connections (cleartext h2c or TLS h2), receive requests, send responses
- **Client**: Initiate outgoing HTTP/2 connections, send requests, receive responses
- **TLS**: ALPN h2 negotiation, SNI-based certificate selection with per-connection domain tags
- **Mutual TLS**: Server-side client certificate verification; client-side certificate presentation
- **io_uring**: All I/O is async via io_uring provided buffers, including optional `IORING_SETUP_SQPOLL`
- **Multi-threaded**: Shared-nothing worker model via `SO_REUSEPORT`; each thread gets its own contexts

## Building

Requires CMake 3.25+ and a C23-capable compiler. Dependencies (shift, shift-io, nghttp2) are fetched automatically.

```bash
# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build

# Release build
cmake -B build-release -DCMAKE_BUILD_TYPE=Release && cmake --build build-release

# Without TLS (skips OpenSSL dependency)
cmake -B build -DENABLE_TLS=OFF && cmake --build build

# Without examples
cmake -B build -DBUILD_EXAMPLES=OFF && cmake --build build
```

## Examples

### Server — cleartext h2c echo

```bash
# Arg is number of worker threads
./build/examples/h2c_echo 4
```

Echoes request headers and body back as the response. Demonstrates the multi-threaded worker pattern with CPU pinning.

### Server — TLS h2 echo

```bash
./build/examples/h2_echo cert.pem key.pem [workers]
```

Same echo behavior over TLS with ALPN h2 negotiation. Includes SNI callback for multi-tenant certificate selection.

### Server — mTLS echo

```bash
./build/examples/h2_mtls_echo server-cert.pem server-key.pem client-ca.pem
```

TLS echo server that requires client certificates. Connections without a valid client cert are rejected during the TLS handshake.

### Client — cleartext h2c

```bash
./build/examples/h2c_client [host] [port] [path]
# Default: GET http://127.0.0.1:9000/
```

### Client — TLS h2 (with optional mTLS)

```bash
./build/examples/h2_client host port [path] [--cert c.pem --key k.pem] [--ca ca.pem] [--no-verify]
```

## Architecture

```
Application
    └── shift-h2   (HTTP/2 server + client)
            ├── shift      (ECS: entities, components, collections)
            ├── shift-io   (io_uring: accept, read, write, connect)
            └── nghttp2    (HTTP/2 wire protocol)
```

### Server data flow

```
shift-io accept → nghttp2 decode → request entity → request_out
                                                         │
                                        app processes request, builds response
                                                         │
response_result_out ← response_sending ← response_in ←──┘
        │
   app destroys entity
```

### Client data flow

```
connect_out → shift-io connect → TLS handshake → nghttp2 client session
                                                         │
connect_result_out (session entity) ←────────────────────┘
        │
   app creates request with session
        │
request_in → nghttp2 submit_request → response entity → response_out
                                                              │
                                              response_result_out (stream close)
                                                              │
                                                    app destroys entity
```

### Connection lifecycle

States: `NEW → TLS_HANDSHAKE (if TLS) → ACTIVE → CLOSED`

Direction (server vs client) is encoded as **collection membership**, not flags. Reads are triaged into direction-specific collections with separate processing functions:

| Collection | Direction | Purpose |
|---|---|---|
| `coll_read_init` | Server | New server connections |
| `coll_read_client_init` | Client | New client connections |
| `coll_read_handshake` | Server | Server TLS handshakes |
| `coll_read_client_handshake` | Client | Client TLS handshakes |
| `coll_read_active` | Both | Active data → nghttp2 |
| `coll_read_errors` | Both | Errors/EOF → cleanup |

## Usage

### Setup sequence

```c
// 1. Create shift context
shift_t *sh;
shift_context_create(&(shift_config_t){
    .max_entities = 65536,
    .max_components = 32,
    .max_collections = 32,
    .deferred_queue_capacity = 65536,
}, &sh);

// 2. Register components
sh2_component_ids_t comp;
sh2_register_components(sh, &comp);

// 3. Create collections with all sh2 components
shift_component_id_t all[] = {
    comp.stream_id, comp.session, comp.req_headers, comp.req_body,
    comp.resp_headers, comp.resp_body, comp.status, comp.io_result,
    comp.domain_tag,
};
shift_collection_id_t request_out, response_in, response_result_out;
// ... register each with shift_collection_register() ...

// 4. Create sh2 context
sh2_context_t *ctx;
sh2_context_create(&(sh2_config_t){
    .shift           = sh,
    .comp_ids        = comp,
    .max_connections = 16384,
    .ring_entries    = 32768,
    .buf_count       = 32768,
    .buf_size        = 65536,
    .request_out         = request_out,
    .response_in         = response_in,
    .response_result_out = response_result_out,
}, &ctx);

// 5. Listen (server) or connect (client)
sh2_listen(ctx, 9000, 4096);
```

### Server event loop

```c
while (running) {
    sh2_poll(ctx, 0);

    // Read completed requests
    shift_entity_t *entities;
    size_t count;
    shift_collection_get_entities(sh, request_out, &entities, &count);

    for (size_t i = 0; i < count; i++) {
        // Read request components
        sh2_req_headers_t *rh;
        shift_entity_get_component(sh, entities[i], comp.req_headers, (void **)&rh);

        // Build response (fields array must be malloc'd)
        sh2_resp_headers_t *resp_h;
        shift_entity_get_component(sh, entities[i], comp.resp_headers, (void **)&resp_h);
        resp_h->fields = malloc(sizeof(sh2_header_field_t));
        resp_h->fields[0] = (sh2_header_field_t){
            .name = "content-type", .name_len = 12,
            .value = "text/plain",  .value_len = 10,
        };
        resp_h->count = 1;

        sh2_status_t *st;
        shift_entity_get_component(sh, entities[i], comp.status, (void **)&st);
        st->code = 200;

        shift_entity_move_one(sh, entities[i], response_in);
    }

    // Drain completed responses
    shift_collection_get_entities(sh, response_result_out, &entities, &count);
    for (size_t i = 0; i < count; i++)
        shift_entity_destroy_one(sh, entities[i]);

    shift_flush(sh);
}
```

### Client connection and request

```c
// Create connect entity
shift_entity_t ce;
shift_entity_create_one_begin(sh, connect_out, &ce);
sh2_connect_target_t *tgt;
shift_entity_get_component(sh, ce, comp.connect_target, (void **)&tgt);
tgt->addr = (struct sockaddr_in){
    .sin_family = AF_INET,
    .sin_port   = htons(443),
};
inet_pton(AF_INET, "93.184.216.34", &tgt->addr.sin_addr);
tgt->hostname     = "example.com";
tgt->hostname_len = 11;
shift_entity_create_one_end(sh, ce);

// In event loop: check connect_result_out for session entity,
// then create request entity in request_in with:
//   session (from connect result), req_headers (with pseudo-headers), req_body
```

### TLS configuration

```c
// Server TLS with SNI
sh2_tls_config_t *tls;
sh2_tls_config_create(&tls);
sh2_cert_id_t cert_id;
sh2_tls_config_add_cert(tls, cert_pem, key_pem, &cert_id);
sh2_tls_config_set_sni_callback(tls, my_sni_callback, user_data);

// Server mTLS — require client certificates
sh2_tls_config_set_client_verify(tls,
    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ca_pem);

// Client TLS with mTLS presentation
sh2_tls_client_config_t *client_tls;
sh2_tls_client_config_create(&client_tls);
sh2_tls_client_config_set_cert(client_tls, cert_pem, key_pem);
sh2_tls_client_config_add_ca(client_tls, ca_pem);
```

## Memory ownership

| Component | Allocated by | Freed by |
|---|---|---|
| `req_headers.fields` | shift-h2 | shift-h2 destructor |
| `req_body.data` | shift-h2 | shift-h2 destructor |
| `resp_headers.fields` | App (`malloc`) | shift-h2 destructor |
| `resp_body.data` | App (`malloc`) | shift-h2 destructor |

Response header `name`/`value` pointers are **not** freed by the destructor. They may be string literals, stack pointers, or embedded in the fields allocation.

## Load testing

```bash
# Requires h2load from nghttp2-tools
./scripts/load_test.sh quick       #   1k reqs, 10 clients
./scripts/load_test.sh moderate    # 100k reqs, 100 clients (default)
./scripts/load_test.sh heavy       #   1M reqs, 500 clients
./scripts/load_test.sh sustained   #  10M reqs, 1000 clients

# Environment overrides
HOST=10.0.0.1 PORT=8080 BODY_SIZE=1024 ./scripts/load_test.sh heavy
NO_SERVER=1 ./scripts/load_test.sh moderate  # BYO server
```

## Threading model

Each worker thread creates independent shift, shift-io, and shift-h2 contexts. Workers share nothing. The kernel distributes connections across workers via `SO_REUSEPORT`. See `h2c_echo.c` for the full pattern including CPU pinning.

## License

See LICENSE file.
