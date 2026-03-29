#pragma once

#include <shift_h2.h>
#include <shift_io.h>
#include <nghttp2/nghttp2.h>
#include <stdbool.h>
#include <stdio.h>

/* --------------------------------------------------------------------------
 * Internal connection index component (on sio connection_results entities)
 * -------------------------------------------------------------------------- */

typedef struct {
    uint32_t idx;
    uint8_t  state;     /* SH2_CONN_* */
    uint8_t  direction; /* SH2_DIR_* */
} sh2_conn_idx_t;

#define SH2_CONN_NEW            0
#define SH2_CONN_ACTIVE         1
#define SH2_CONN_CLOSED         2
#define SH2_CONN_TLS_HANDSHAKE  3

#define SH2_DIR_SERVER          0
#define SH2_DIR_CLIENT          1

/* --------------------------------------------------------------------------
 * Per-connection state
 * -------------------------------------------------------------------------- */

#ifdef SH2_HAS_TLS
#include "sh2_tls.h"
#endif

typedef struct sh2_ng_ctx sh2_ng_ctx_t;

typedef struct {
    nghttp2_session   *ng_session;
    sh2_ng_ctx_t      *ng_ctx;           /* nghttp2 session user_data */
    shift_entity_t     conn_entity;      /* sio internal connection entity */
    shift_entity_t     user_conn_entity; /* sio user connection entity */
    uint32_t           pending_writes;   /* outstanding write entities */
    bool               draining;         /* session done, waiting for writes */
    uint64_t           last_active_poll; /* poll tick of last activity */
    char              *hostname;        /* client connections: target hostname (owned) */
#ifdef SH2_HAS_TLS
    sh2_tls_conn_t    *tls;             /* NULL for h2c connections */
#endif
} sh2_conn_t;

/* --------------------------------------------------------------------------
 * Per-stream accumulation (nghttp2 stream user_data)
 * -------------------------------------------------------------------------- */

typedef struct {
    uint32_t            conn_idx;
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
} sh2_stream_t;

/* --------------------------------------------------------------------------
 * nghttp2 session user_data wrapper
 * -------------------------------------------------------------------------- */

struct sh2_ng_ctx {
    sh2_context_t *ctx;
    uint32_t       conn_idx;
};

/* --------------------------------------------------------------------------
 * Response body send tracking (nghttp2 data provider source)
 * -------------------------------------------------------------------------- */

typedef struct {
    const void *data;
    uint32_t    len;
    uint32_t    offset;
} sh2_resp_data_t;

/* --------------------------------------------------------------------------
 * Library context
 * -------------------------------------------------------------------------- */

struct sh2_context {
    shift_t                    *shift;
    sh2_component_ids_t         comp_ids;
    sh2_collection_ids_t        coll_ids;
    shift_collection_id_t       coll_response_sending;

    /* shift-io */
    sio_context_t              *sio;
    sio_component_ids_t         sio_comp_ids;
    shift_collection_id_t       sio_connection_results;
    shift_collection_id_t       sio_read_results;
    shift_collection_id_t       sio_write_results;

    /* internal conn_idx component */
    shift_component_id_t        internal_conn_idx;

    /* internal read processing collections (same archetype as sio_read_results) */
    shift_collection_id_t       coll_read_errors;  /* error/EOF/stale → destroy */
    shift_collection_id_t       coll_read_init;    /* new conns → lazy init */
    shift_collection_id_t       coll_read_active;  /* active data → feed nghttp2 */

    /* connections */
    sh2_conn_t                 *conns;
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
    shift_collection_id_t       sio_connect_results;
    shift_collection_id_t       coll_client_request_sending;
    shift_collection_id_t       coll_read_client_init;
    shift_collection_id_t       coll_read_client_handshake;
    nghttp2_session_callbacks  *ng_client_callbacks;

#ifdef SH2_HAS_TLS
    /* TLS state (client) */
    SSL_CTX                    *ssl_client_ctx;
    sh2_tls_client_config_t    *tls_client_config;
#endif
};
