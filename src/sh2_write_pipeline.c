#include "sh2_poll_internal.h"
#include "sh2_nghttp2.h"

/* --------------------------------------------------------------------------
 * Write pass 1: free data, decrement pending_writes, close error connections
 * -------------------------------------------------------------------------- */

void sh2_writes_account_and_close(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;

  shift_entity_t *entities = NULL;
  sio_write_buf_t *wbufs = NULL;
  sio_io_result_t *results = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->sio_write_results, &entities, &count);
  if (count == 0)
    return;

  shift_collection_get_component_array(sh, ctx->sio_write_results,
                                       ctx->sio_comp_ids.write_buf,
                                       (void **)&wbufs, NULL);
  shift_collection_get_component_array(sh, ctx->sio_write_results,
                                       ctx->sio_comp_ids.io_result,
                                       (void **)&results, NULL);
  shift_collection_get_component_array(sh, ctx->sio_write_results,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    /* free the copied send data */
    free((void *)wbufs[i].data);
    wbufs[i].data = NULL;

    shift_entity_t user_conn = uconns[i].entity;
    if (shift_entity_is_stale(sh, user_conn) ||
        shift_entity_is_moving(sh, user_conn)) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy write entity (stale)");
      continue;
    }

    sh2_conn_t *conn = sh2_conn_get(ctx, user_conn);
    if (!conn) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy write entity (no conn)");
      continue;
    }

    if (conn->pending_writes > 0)
      conn->pending_writes--;

    conn->last_active_ns = sh2_monotonic_ns();

    /* on write error, close active connection */
    if (results[i].error != 0) {
      shift_collection_id_t conn_coll = 0;
      shift_entity_get_collection(sh, user_conn, &conn_coll);
      if (conn_coll == ctx->coll_conn_active)
        sh2_conn_close(ctx, user_conn);
    }

    SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
              "destroy write entity");
  }
}

/* --------------------------------------------------------------------------
 * Write pass 2: finalize draining connections (all writes complete)
 * -------------------------------------------------------------------------- */

void sh2_writes_finalize_draining(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;

  shift_entity_t *entities = NULL;
  size_t count = 0;
  shift_collection_get_entities(sh, ctx->coll_conn_draining, &entities, &count);

  for (size_t i = 0; i < count; i++) {
    sh2_conn_t *conn = sh2_conn_get(ctx, entities[i]);
    if (!conn || conn->pending_writes > 0)
      continue;

    if (!shift_entity_is_stale(sh, conn->conn_entity))
      SH2_CHECK(shift_entity_destroy_one(sh, conn->conn_entity),
                "destroy conn_entity (drain)");
    /* Destroying user_conn_entity triggers conn_dtor which cleans up
     * remaining resources (hostname, etc.) */
    if (!shift_entity_is_stale(sh, entities[i]))
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy user_conn (drain)");
  }
}
