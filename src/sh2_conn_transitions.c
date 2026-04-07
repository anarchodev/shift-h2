#include "sh2_poll_internal.h"

/* --------------------------------------------------------------------------
 * Connection state transitions
 *
 * These run AFTER reads_init_connections / reads_init_client_connections are
 * flushed.  They move user_conn entities between state collections based on
 * which fields are populated — no other system needs to do state moves.
 * -------------------------------------------------------------------------- */

/* Move NEW connections (in sio_connection_results) to their next state */
void sh2_transition_new_connections(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->sio_connection_results,
                                &entities, &count);
  for (size_t i = 0; i < count; i++) {
    sh2_conn_t *conn = sh2_conn_get(ctx, entities[i]);
    if (!conn) continue;

    if (conn->ng_session) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_conn_active),
                "transition: new → active");
    }
#ifdef SH2_HAS_TLS
    else if (conn->tls) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_conn_tls_handshake),
                "transition: new → tls_handshake");
    }
#endif
  }
}

#ifdef SH2_HAS_TLS
/* Move completed TLS handshakes to active */
void sh2_transition_handshake_connections(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_conn_tls_handshake,
                                &entities, &count);
  for (size_t i = 0; i < count; i++) {
    sh2_conn_t *conn = sh2_conn_get(ctx, entities[i]);
    if (!conn) continue;

    if (conn->ng_session) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_conn_active),
                "transition: tls_handshake → active");
    }
  }
}
#endif
