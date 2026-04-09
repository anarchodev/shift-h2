#pragma once

#include <shift_h2.h>
#include <shift_io.h>
#include <nghttp2/nghttp2.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* --------------------------------------------------------------------------
 * Connection state constants
 * -------------------------------------------------------------------------- */

#define SH2_DIR_SERVER          0
#define SH2_DIR_CLIENT          1

/* Sentinel for "no entity" — zero is a valid entity ID in shift. */
#define SH2_ENTITY_NONE ((shift_entity_t){ .index = UINT32_MAX, .generation = UINT32_MAX })

static inline bool sh2_entity_is_none(shift_entity_t e) {
    return e.index == UINT32_MAX && e.generation == UINT32_MAX;
}

/* Error code used when a stream closes before the response body is fully
 * sent — distinguishes "send interrupted" from a clean close. */
#define SH2_ERR_SEND_INCOMPLETE 1

/* Fatal shift operation check — aborts on failure with file/line info. */
#define SH2_CHECK(expr, msg) do {                                    \
    shift_result_t _r = (expr);                                      \
    if (_r != shift_ok) {                                            \
      fprintf(stderr, "FATAL [%s:%d] %s failed: %d\n",              \
              __FILE__, __LINE__, (msg), _r);                        \
      abort();                                                       \
    }                                                                \
  } while (0)

/* --------------------------------------------------------------------------
 * Per-connection state — registered as an internal component on user_conn
 * entities.  Destruction of the entity triggers the component destructor
 * which cleans up nghttp2, TLS, and hostname resources.
 * -------------------------------------------------------------------------- */

/* Forward declare TLS per-connection state so sh2_conn_t can hold a pointer */
typedef struct sh2_tls_conn sh2_tls_conn_t;
typedef struct sh2_ng_ctx sh2_ng_ctx_t;

typedef struct sh2_conn {
    uint8_t            direction;       /* SH2_DIR_* */
    nghttp2_session   *ng_session;
    sh2_ng_ctx_t      *ng_ctx;           /* nghttp2 session user_data */
    shift_entity_t     conn_entity;      /* sio internal connection entity */
    uint32_t           pending_writes;   /* outstanding write entities */
    uint64_t           last_active_ns;   /* CLOCK_MONOTONIC nanos of last activity */
    char              *hostname;        /* client connections: target hostname (owned) */
    shift_entity_t     pending_user_entity; /* user's connect_in entity in connect_pending;
                                            * SH2_ENTITY_NONE for server connections */
#ifdef SH2_HAS_TLS
    sh2_tls_conn_t    *tls;             /* NULL for h2c connections */
#endif
} sh2_conn_t;

#ifdef SH2_HAS_TLS
#include "sh2_tls.h"
#endif

/* --------------------------------------------------------------------------
 * Internal connect entity handle — carried on sio connect entities so the
 * user's original connect_in entity can be correlated back after sio
 * completes the TCP connect.
 * -------------------------------------------------------------------------- */

typedef struct {
    shift_entity_t entity;  /* user's connect_in entity, parked in connect_pending;
                             * SH2_ENTITY_NONE for server-accepted connections */
} sh2_connect_entity_t;

/* --------------------------------------------------------------------------
 * Body send tracking (nghttp2 data provider source)
 * Used for both server response bodies and client request bodies.
 * -------------------------------------------------------------------------- */

typedef struct {
    const void *data;
    uint32_t    len;
    uint32_t    offset;
} sh2_body_data_t;

/* --------------------------------------------------------------------------
 * Per-stream accumulation (nghttp2 stream user_data)
 * -------------------------------------------------------------------------- */

typedef struct {
    shift_entity_t      conn_entity;
    sh2_header_field_t *hdr_fields;
    uint32_t            hdr_count;
    uint32_t            hdr_cap;
    char               *hdr_strbuf;
    uint32_t            hdr_strbuf_len;
    uint32_t            hdr_strbuf_cap;
    uint8_t            *body_data;
    uint32_t            body_len;
    uint32_t            body_cap;
    shift_entity_t      entity;
    bool                emitted;
    bool                send_complete;
    uint16_t            response_status; /* parsed :status for client mode */
    sh2_body_data_t    *send_data;       /* owned; freed on EOF or early close */
} sh2_stream_t;

/* --------------------------------------------------------------------------
 * nghttp2 session user_data wrapper
 * -------------------------------------------------------------------------- */

struct sh2_ng_ctx {
    sh2_context_t     *ctx;
    shift_entity_t     conn_entity;
};

/* --------------------------------------------------------------------------
 * Library context
 * -------------------------------------------------------------------------- */

struct sh2_context {
    shift_t                    *shift;
    sh2_component_ids_t         comp_ids;
    bool                        client_only;
    sh2_collection_ids_t        coll_ids;
    shift_collection_id_t       coll_response_sending;

    /* shift-io */
    sio_context_t              *sio;
    sio_component_ids_t         sio_comp_ids;
    shift_collection_id_t       sio_connections;     /* sio-managed connection entities */
    shift_collection_id_t       sio_read_results;
    shift_collection_id_t       sio_write_results;

    /* internal connection component (sh2_conn_t) on connection entities */
    shift_component_id_t        internal_conn;

    /* connection state collections (connection entities move between these) */
    /* NEW state = sio_connections (sio creates/moves connection entities there) */
    shift_collection_id_t       coll_conn_active;        /* nghttp2 session live */
    shift_collection_id_t       coll_conn_tls_handshake; /* TLS handshake in progress */
    shift_collection_id_t       coll_conn_draining;      /* session gone, writes pending */

    /* internal read processing collections (same archetype as sio_read_results) */
    shift_collection_id_t       coll_read_errors;  /* error/EOF/stale → destroy */
    shift_collection_id_t       coll_read_init;    /* new conns → lazy init */
    shift_collection_id_t       coll_read_active;  /* active data → feed nghttp2 */

    /* connection limits */
    uint32_t                    max_connections;

    /* nghttp2 shared callbacks */
    nghttp2_session_callbacks  *ng_callbacks;

    /* poll tick counter (for idle connection detection) */
    uint64_t                    poll_count;

#ifdef SH2_HAS_TLS
    /* TLS state (server) */
    SSL_CTX                    *ssl_ctx;
    sh2_tls_config_t           *tls_config;     /* borrowed ref to user config */
    shift_collection_id_t       coll_read_handshake; /* TLS handshake data */
#endif

    /* client / outgoing connection support */
    bool                        enable_connect;
    sh2_client_collection_ids_t coll_ids_client;
    shift_collection_id_t       sio_connect_errors;          /* sio failed connect entities */
    shift_collection_id_t       coll_connect_pending;        /* user entities parked during sio connect */
    shift_collection_id_t       coll_client_request_sending;
    shift_collection_id_t       coll_read_client_init;
    shift_collection_id_t       coll_read_client_handshake;
    nghttp2_session_callbacks  *ng_client_callbacks;

    /* internal component for connect entities */
    shift_component_id_t        internal_connect_entity;

#ifdef SH2_HAS_TLS
    /* TLS state (client) */
    SSL_CTX                    *ssl_client_ctx;
    sh2_tls_client_config_t    *tls_client_config;
#endif
};

/* --------------------------------------------------------------------------
 * Helper: get sh2_conn_t component from a user_conn entity
 * -------------------------------------------------------------------------- */

static inline sh2_conn_t *sh2_conn_get(sh2_context_t *ctx,
                                        shift_entity_t conn_entity) {
    sh2_conn_t *conn = NULL;
    shift_entity_get_component(ctx->shift, conn_entity,
                               ctx->internal_conn, (void **)&conn);
    return conn;
}
