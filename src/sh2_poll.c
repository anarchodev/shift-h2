#include "sh2_nghttp2.h"
#include "shift_h2_internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SH2_CHECK(expr, msg) do {                                    \
    shift_result_t _r = (expr);                                      \
    if (_r != shift_ok) {                                            \
      fprintf(stderr, "FATAL [%s:%d] %s failed: %d\n",              \
              __FILE__, __LINE__, (msg), _r);                        \
      abort();                                                       \
    }                                                                \
  } while (0)

/* --------------------------------------------------------------------------
 * Consume response_in collection
 * -------------------------------------------------------------------------- */

static void consume_responses(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;
  shift_collection_id_t coll = ctx->coll_ids.response_in;
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, coll, &entities, &count);
  if (count == 0)
    return;

  sh2_session_t *sessions = NULL;
  sh2_stream_id_t *sids = NULL;
  sh2_status_t *statuses = NULL;
  sh2_resp_headers_t *rhs = NULL;
  sh2_resp_body_t *rbs = NULL;
  sh2_io_result_t *ios = NULL;

  shift_collection_get_component_array(sh, coll, ctx->comp_ids.session,
                                       (void **)&sessions, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.stream_id,
                                       (void **)&sids, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.status,
                                       (void **)&statuses, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.resp_headers,
                                       (void **)&rhs, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.resp_body,
                                       (void **)&rbs, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.io_result,
                                       (void **)&ios, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t entity = entities[i];
    sh2_session_t *sess = &sessions[i];
    sh2_stream_id_t *sid = &sids[i];
    sh2_status_t *status = &statuses[i];
    sh2_resp_headers_t *rh = &rhs[i];
    sh2_resp_body_t *rb = &rbs[i];

    /* find connection */
    if (shift_entity_is_stale(sh, sess->entity)) {
      ios[i].error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_result_out),
                "move stale entity to result_out");
      continue;
    }

    /* find conn_idx by matching user_conn_entity */
    uint32_t conn_idx = UINT32_MAX;
    for (uint32_t j = 0; j < ctx->max_connections; j++) {
      if (ctx->conns[j].ng_session &&
          ctx->conns[j].user_conn_entity.index == sess->entity.index &&
          ctx->conns[j].user_conn_entity.generation ==
              sess->entity.generation) {
        conn_idx = j;
        break;
      }
    }
    if (conn_idx == UINT32_MAX) {
      ios[i].error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_result_out),
                "move orphan entity to result_out");
      continue;
    }

    sh2_conn_t *conn = &ctx->conns[conn_idx];

    /* build nghttp2_nv array: :status + response headers */
    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%u", status->code);

    uint32_t nv_count = 1 + rh->count;
    nghttp2_nv *nva = malloc(nv_count * sizeof(nghttp2_nv));
    if (!nva) continue;

    nva[0] = (nghttp2_nv){
        .name     = (uint8_t *)":status",
        .namelen  = 7,
        .value    = (uint8_t *)status_str,
        .valuelen = strlen(status_str),
        .flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME,
    };

    for (uint32_t j = 0; j < rh->count; j++) {
      nva[1 + j] = (nghttp2_nv){
          .name     = (uint8_t *)rh->fields[j].name,
          .namelen  = rh->fields[j].name_len,
          .value    = (uint8_t *)rh->fields[j].value,
          .valuelen = rh->fields[j].value_len,
          .flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME |
                      NGHTTP2_NV_FLAG_NO_COPY_VALUE,
      };
    }

    /* data provider for response body — copy the body so the provider
     * is independent of user-owned memory lifetime */
    nghttp2_data_provider data_prd = {0};
    if (rb->data && rb->len > 0) {
      sh2_resp_data_t *rd = malloc(sizeof(*rd) + rb->len);
      if (rd) {
        void *copy = (uint8_t *)rd + sizeof(*rd);
        memcpy(copy, rb->data, rb->len);
        rd->data   = copy;
        rd->len    = rb->len;
        rd->offset = 0;
        data_prd.source.ptr    = rd;
        data_prd.read_callback = on_data_source_read;
      }
    }

    nghttp2_submit_response(conn->ng_session, (int32_t)sid->id, nva, nv_count,
                            data_prd.read_callback ? &data_prd : NULL);
    free(nva);

    /* move entity to internal sending collection */
    SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_response_sending),
              "move entity to sending");

    /* find the stream and associate the entity with it */
    sh2_stream_t *stream =
        nghttp2_session_get_stream_user_data(conn->ng_session, (int32_t)sid->id);
    if (stream) {
      stream->entity        = entity;
      stream->emitted       = true;
      stream->send_complete = !data_prd.read_callback;
    } else {
      /* stream already closed (peer reset, connection teardown, etc.)
       * — move entity straight to result_out so it doesn't leak */
      sh2_io_result_t *io = NULL;
      SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.io_result,
                                            (void **)&io),
                "get io_result (no-stream)");
      io->error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_result_out),
                "move no-stream entity to result_out");
    }
  }
}

/* --------------------------------------------------------------------------
 * Drive all connections that have pending nghttp2 output
 * -------------------------------------------------------------------------- */

/* Idle threshold: evict connections with no activity for this many polls.
 * nghttp2 silently drops certain protocol violations (e.g. frames on
 * evicted closed streams) without generating error responses, leaving
 * sessions stuck with want_read=1 and no data flowing. */
#define SH2_IDLE_POLL_THRESHOLD 100000

static void drive_all_sends(sh2_context_t *ctx) {
  uint32_t driven = 0;
  for (uint32_t i = 0; i < ctx->max_connections; i++) {
    if (!ctx->conns[i].ng_session)
      continue;

    /* evict idle connections — safety net for zombie sessions */
    if (ctx->poll_count - ctx->conns[i].last_active_poll > SH2_IDLE_POLL_THRESHOLD) {
      SH2_DBG("[idle_evict] conn=%u idle=%lu polls\n",
              i, (unsigned long)(ctx->poll_count - ctx->conns[i].last_active_poll));
      sh2_conn_close(ctx, i);
      continue;
    }

    /* drive sessions that want to write, OR sessions that are done
     * (neither want_read nor want_write) — the latter need teardown
     * which happens inside sh2_drive_send after the send loop */
    if (nghttp2_session_want_write(ctx->conns[i].ng_session) ||
        !nghttp2_session_want_read(ctx->conns[i].ng_session)) {
      sh2_drive_send(ctx, i);
      ctx->conns[i].last_active_poll = ctx->poll_count;
      driven++;
    }
  }
  static _Thread_local uint64_t call_count = 0;
  call_count++;
  if (driven > 0 && call_count % 1000 == 0)
    SH2_DBG("[drive_all] driven=%u\n", driven);
}

/* --------------------------------------------------------------------------
 * Process sio read results — multi-pass to avoid deferred-op conflicts
 * -------------------------------------------------------------------------- */

/* Pass 1: Triage — sort read results into errors, new-conn, or active */
static void reads_triage(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;

  shift_entity_t *entities = NULL;
  sio_read_buf_t *rbufs = NULL;
  sio_io_result_t *results = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->sio_read_results, &entities, &count);
  if (count == 0)
    return;

  shift_collection_get_component_array(sh, ctx->sio_read_results,
                                       ctx->sio_comp_ids.read_buf,
                                       (void **)&rbufs, NULL);
  shift_collection_get_component_array(sh, ctx->sio_read_results,
                                       ctx->sio_comp_ids.io_result,
                                       (void **)&results, NULL);
  shift_collection_get_component_array(sh, ctx->sio_read_results,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_conn = uconns[i].entity;

    /* connection already torn down */
    if (shift_entity_is_stale(sh, user_conn) ||
        shift_entity_is_moving(sh, user_conn)) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_errors),
                "triage: stale → errors");
      continue;
    }

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (triage)");

    /* error, EOF, or already closed */
    if (results[i].error != 0 || rbufs[i].len == 0 ||
        cidx->state == SH2_CONN_CLOSED) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_errors),
                "triage: error/EOF → errors");
      continue;
    }

    /* new connection needing init */
    if (cidx->state == SH2_CONN_NEW) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_init),
                "triage: new → init");
      continue;
    }

    /* active connection with data */
    SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_active),
              "triage: active → active");
  }
}

/* Pass 2: Handle errors — close connections, destroy read entities */
static void reads_handle_errors(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;

  shift_entity_t *entities = NULL;
  sio_io_result_t *results = NULL;
  sio_conn_entity_t *conns = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_errors, &entities, &count);
  if (count == 0)
    return;

  shift_collection_get_component_array(sh, ctx->coll_read_errors,
                                       ctx->sio_comp_ids.io_result,
                                       (void **)&results, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_errors,
                                       ctx->sio_comp_ids.conn_entity,
                                       (void **)&conns, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_errors,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_conn = uconns[i].entity;

    if (!shift_entity_is_stale(sh, user_conn) &&
        !shift_entity_is_moving(sh, user_conn)) {
      sh2_conn_idx_t *cidx = NULL;
      SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                            (void **)&cidx),
                "get conn_idx (errors)");

      if (cidx->state == SH2_CONN_ACTIVE) {
        sh2_conn_close(ctx, cidx->idx);
      } else if (cidx->state == SH2_CONN_NEW) {
        if (!shift_entity_is_stale(sh, conns[i].entity))
          SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                    "destroy conn_entity (error new)");
        if (!shift_entity_is_stale(sh, user_conn))
          SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                    "destroy user_conn (error new)");
      }
    }

    SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
              "destroy read entity (error)");
  }
}

/* Pass 3: Init new connections */
static void reads_init_connections(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  sio_conn_entity_t *conns = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_init, &entities, &count);
  if (count == 0)
    return;

  shift_collection_get_component_array(sh, ctx->coll_read_init,
                                       ctx->sio_comp_ids.conn_entity,
                                       (void **)&conns, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_init,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_conn = uconns[i].entity;

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (init)");

    uint32_t conn_idx = UINT32_MAX;
    for (uint32_t j = 0; j < ctx->max_connections; j++) {
      if (!ctx->conns[j].ng_session) {
        conn_idx = j;
        break;
      }
    }

    if (conn_idx == UINT32_MAX) {
      /* no room — close the connection */
      SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                "destroy conn_entity (no room)");
      SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                "destroy user_conn (no room)");
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (no room)");
      continue;
    }

    cidx->idx = conn_idx;
    cidx->state = SH2_CONN_ACTIVE;

    sh2_conn_t *conn = &ctx->conns[conn_idx];
    *conn = (sh2_conn_t){
        .conn_entity = conns[i].entity,
        .user_conn_entity = user_conn,
        .last_active_poll = ctx->poll_count,
    };

    if (sh2_nghttp2_session_create(ctx, conn_idx) != sh2_ok) {
      SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                "destroy conn_entity (session fail)");
      SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                "destroy user_conn (session fail)");
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (session fail)");
      *conn = (sh2_conn_t){0};
      cidx->state = SH2_CONN_NEW;
      continue;
    }

    /* move to active for data feeding */
    SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_active),
              "init → active");
  }
}

/* Pass 4: Feed active data to nghttp2 */
static void reads_feed_data(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  sio_read_buf_t *rbufs = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_active, &entities, &count);
  if (count == 0)
    return;

  shift_collection_get_component_array(sh, ctx->coll_read_active,
                                       ctx->sio_comp_ids.read_buf,
                                       (void **)&rbufs, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_active,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_conn = uconns[i].entity;

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (feed)");

    sh2_conn_t *conn = &ctx->conns[cidx->idx];

    if (!conn->ng_session) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (no session)");
      continue;
    }

    nghttp2_ssize consumed =
        nghttp2_session_mem_recv(conn->ng_session, rbufs[i].data, rbufs[i].len);

    if (consumed < 0) {
      sh2_conn_close(ctx, cidx->idx);
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (recv error)");
      continue;
    }

    conn->last_active_poll = ctx->poll_count;

    /* recycle read buffer */
    SH2_CHECK(shift_entity_move_one(sh, entities[i], sio_colls->read_in),
              "recycle read buffer");
  }
}

/* --------------------------------------------------------------------------
 * Process sio write results — multi-pass to avoid deferred-op conflicts
 * -------------------------------------------------------------------------- */

/* Write pass 1: free data, decrement pending_writes, close error connections */
static void writes_account_and_close(sh2_context_t *ctx) {
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

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (writes_account)");

    if (cidx->idx >= ctx->max_connections) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy write entity (bad idx)");
      continue;
    }

    sh2_conn_t *conn = &ctx->conns[cidx->idx];

    if (conn->pending_writes > 0)
      conn->pending_writes--;

    conn->last_active_poll = ctx->poll_count;

    /* on write error, close active connection */
    if (results[i].error != 0 && cidx->state == SH2_CONN_ACTIVE)
      sh2_conn_close(ctx, cidx->idx);

    SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
              "destroy write entity");
  }
}

/* Write pass 2: finalize draining connections (all writes complete) */
static void writes_finalize_draining(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;

  for (uint32_t i = 0; i < ctx->max_connections; i++) {
    sh2_conn_t *conn = &ctx->conns[i];
    if (!conn->draining || conn->pending_writes > 0)
      continue;

    if (!shift_entity_is_stale(sh, conn->conn_entity))
      SH2_CHECK(shift_entity_destroy_one(sh, conn->conn_entity),
                "destroy conn_entity (drain)");
    if (!shift_entity_is_stale(sh, conn->user_conn_entity))
      SH2_CHECK(shift_entity_destroy_one(sh, conn->user_conn_entity),
                "destroy user_conn (drain)");
    *conn = (sh2_conn_t){0};
  }
}

/* --------------------------------------------------------------------------
 * sh2_poll
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_poll(sh2_context_t *ctx, uint32_t min_complete) {
  if (!ctx)
    return sh2_error_null;

  static _Thread_local uint64_t last_active = 0;
  uint64_t poll_count = ++ctx->poll_count;

  sio_result_t sr = sio_poll(ctx->sio, min_complete);
  if (sr != sio_ok) {
    fprintf(stderr, "[poll #%lu] sio_poll failed: %d\n",
            (unsigned long)poll_count, sr);
    return sh2_error_io;
  }

  /* consume responses queued by user since last poll — submit to nghttp2
   * and move entities to coll_response_sending */
  consume_responses(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* read pass 1: triage into errors / init / active */
  reads_triage(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* read pass 2: handle errors — close connections, destroy entities */
  reads_handle_errors(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* read pass 3: init new connections, move to active */
  reads_init_connections(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* read pass 4: feed active data to nghttp2 */
  reads_feed_data(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* write pass 1: free data, decrement counters, close error connections */
  writes_account_and_close(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* write pass 2: finalize draining connections */
  writes_finalize_draining(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* second pass for responses queued by user during this tick */
  consume_responses(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* drive all nghttp2 output as a separate pass — entities are in
   * coll_response_sending so on_stream_close can safely queue a
   * single deferred move to response_result_out */
  drive_all_sends(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* periodic stats */
  {
    size_t n_resp_in = 0, n_read_res = 0, n_write_res = 0;
    size_t n_req_out = 0, n_sending = 0, n_result = 0;
    size_t n_read_in = 0, n_write_in = 0;
    size_t n_read_err = 0, n_read_init = 0, n_read_active = 0;
    shift_entity_t *tmp = NULL;
    const sio_collection_ids_t *dbg_sio = sio_get_collection_ids(ctx->sio);
    shift_collection_get_entities(ctx->shift, ctx->coll_ids.response_in, &tmp, &n_resp_in);
    shift_collection_get_entities(ctx->shift, ctx->sio_read_results, &tmp, &n_read_res);
    shift_collection_get_entities(ctx->shift, ctx->sio_write_results, &tmp, &n_write_res);
    shift_collection_get_entities(ctx->shift, ctx->coll_ids.request_out, &tmp, &n_req_out);
    shift_collection_get_entities(ctx->shift, ctx->coll_response_sending, &tmp, &n_sending);
    shift_collection_get_entities(ctx->shift, ctx->coll_ids.response_result_out, &tmp, &n_result);
    shift_collection_get_entities(ctx->shift, dbg_sio->read_in, &tmp, &n_read_in);
    shift_collection_get_entities(ctx->shift, dbg_sio->write_in, &tmp, &n_write_in);
    shift_collection_get_entities(ctx->shift, ctx->coll_read_errors, &tmp, &n_read_err);
    shift_collection_get_entities(ctx->shift, ctx->coll_read_init, &tmp, &n_read_init);
    shift_collection_get_entities(ctx->shift, ctx->coll_read_active, &tmp, &n_read_active);

    size_t n_conns_coll = 0;
    shift_collection_get_entities(ctx->shift, dbg_sio->connections, &tmp, &n_conns_coll);

    /* count entities across ALL collections (including sio-internal) */
    size_t n_total_entities = 0;
    size_t n_collections = shift_collection_count(ctx->shift);
    for (size_t c = 1; c < n_collections; c++) {
      n_total_entities += shift_collection_entity_count(ctx->shift, (shift_collection_id_t){(uint32_t)c});
    }

    size_t tracked = n_resp_in + n_read_res + n_write_res + n_req_out +
                     n_sending + n_result + n_read_in + n_write_in +
                     n_read_err + n_read_init + n_read_active + n_conns_coll;
    if (tracked > 0) last_active = poll_count;

    uint32_t active = 0, pending_wr = 0;
    uint32_t want_r = 0, want_w = 0;
    for (uint32_t i = 0; i < ctx->max_connections; i++) {
      if (ctx->conns[i].ng_session) {
        active++;
        if (nghttp2_session_want_read(ctx->conns[i].ng_session)) want_r++;
        if (nghttp2_session_want_write(ctx->conns[i].ng_session)) want_w++;
      }
      pending_wr += ctx->conns[i].pending_writes;
    }

    /* log every 10000 polls, or if idle for 5000 polls with active conns */
    if (poll_count % 10000 == 0 ||
        (active > 0 && poll_count - last_active > 5000 && poll_count % 1000 == 0)) {
      SH2_DBG(
        "[poll #%lu] rd_res=%zu rd_err=%zu rd_init=%zu rd_act=%zu "
        "rd_in=%zu wr_res=%zu wr_in=%zu | resp_in=%zu req_out=%zu "
        "sending=%zu result=%zu | sio_conns=%zu total_ent=%zu "
        "| conns=%u pend_wr=%u want_r=%u want_w=%u idle=%lu\n",
        (unsigned long)poll_count,
        n_read_res, n_read_err, n_read_init, n_read_active,
        n_read_in, n_write_res, n_write_in,
        n_resp_in, n_req_out, n_sending, n_result,
        n_conns_coll, n_total_entities,
        active, pending_wr, want_r, want_w,
        (unsigned long)(poll_count - last_active));
    }
  }

  return sh2_ok;
}
