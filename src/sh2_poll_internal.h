#pragma once

#include "shift_h2_internal.h"

/* Idle threshold: evict connections with no activity for this many polls. */
#define SH2_IDLE_POLL_THRESHOLD 100000

/* --------------------------------------------------------------------------
 * Server: consume response_in and drive sends
 * -------------------------------------------------------------------------- */

void sh2_consume_responses(sh2_context_t *ctx);
void sh2_drive_all_sends(sh2_context_t *ctx);

/* --------------------------------------------------------------------------
 * Read pipeline — multi-pass to avoid deferred-op conflicts
 * -------------------------------------------------------------------------- */

void sh2_reads_triage(sh2_context_t *ctx);
void sh2_reads_handle_errors(sh2_context_t *ctx);
void sh2_reads_init_connections(sh2_context_t *ctx);
void sh2_reads_feed_data(sh2_context_t *ctx);

#ifdef SH2_HAS_TLS
void sh2_reads_tls_handshake(sh2_context_t *ctx);

/* Per-entity TLS handshake step result */
typedef enum {
    SH2_HS_CONTINUE,  /* handshake needs more data — entity already recycled */
    SH2_HS_DONE,      /* handshake complete, ALPN verified — caller creates session */
    SH2_HS_HANDLED,   /* error or stale — entity already destroyed/closed */
} sh2_hs_step_t;

/* Drive one TLS handshake step: feed data, drain wbio, check ALPN.
 * On SH2_HS_DONE, decrypt_buf/decrypt_len contain any post-handshake data
 * that the caller should feed to the newly-created nghttp2 session. */
sh2_hs_step_t sh2_tls_handshake_step(
    sh2_context_t *ctx,
    shift_entity_t read_entity,
    shift_entity_t user_conn,
    const uint8_t *raw_data, uint32_t raw_len,
    uint8_t *decrypt_buf, uint32_t decrypt_cap, uint32_t *decrypt_len);
#endif

/* --------------------------------------------------------------------------
 * Write pipeline
 * -------------------------------------------------------------------------- */

void sh2_writes_account_and_close(sh2_context_t *ctx);
void sh2_writes_finalize_draining(sh2_context_t *ctx);

/* --------------------------------------------------------------------------
 * Connection state transitions
 * -------------------------------------------------------------------------- */

void sh2_transition_new_connections(sh2_context_t *ctx);

#ifdef SH2_HAS_TLS
void sh2_transition_handshake_connections(sh2_context_t *ctx);
#endif

/* --------------------------------------------------------------------------
 * Client: connect, request, cancel, disconnect
 * -------------------------------------------------------------------------- */

void sh2_consume_connect_requests(sh2_context_t *ctx);
void sh2_process_connect_results(sh2_context_t *ctx);
void sh2_reads_init_client_connections(sh2_context_t *ctx);
void sh2_consume_client_requests(sh2_context_t *ctx);
void sh2_consume_client_cancels(sh2_context_t *ctx);
void sh2_consume_client_connect_closes(sh2_context_t *ctx);

#ifdef SH2_HAS_TLS
void sh2_reads_client_tls_handshake(sh2_context_t *ctx);
#endif
