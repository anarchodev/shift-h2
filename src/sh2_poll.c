#include "sh2_poll_internal.h"
#include "sh2_nghttp2.h"

#include <assert.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Consume response_in collection
 * -------------------------------------------------------------------------- */

void sh2_consume_responses(sh2_context_t *ctx) {
  if (ctx->client_only) return;

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

    /* find connection via internal_conn component on session entity */
    sh2_conn_t *conn = NULL;
    if (shift_entity_is_stale(sh, sess->entity) ||
        !(conn = sh2_conn_get(ctx, sess->entity))) {
      ios[i].error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_out),
                "move stale/orphan entity to result_out");
      continue;
    }

    /* build nghttp2_nv array: :status + response headers */
    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%u", status->code);

    uint32_t nv_count = 1 + rh->count;
    nghttp2_nv *nva = malloc(nv_count * sizeof(nghttp2_nv));
    if (!nva) {
      ios[i].error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_out),
                "move OOM entity to result_out");
      continue;
    }

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
      sh2_body_data_t *rd = sh2_body_data_alloc(rb->data, rb->len);
      if (!rd) {
        free(nva);
        ios[i].error = -1;
        SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_out),
                  "move body-OOM entity to result_out");
        continue;
      }
      data_prd.source.ptr    = rd;
      data_prd.read_callback = on_data_source_read;
    }

    int rv = nghttp2_submit_response(conn->ng_session, (int32_t)sid->id, nva,
                                      nv_count,
                                      data_prd.read_callback ? &data_prd : NULL);
    free(nva);
    if (rv < 0) {
      ios[i].error = -1;
      if (data_prd.source.ptr) free(data_prd.source.ptr);
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_out),
                "move submit_response error to result_out");
      continue;
    }

    /* find the stream and associate the entity with it — must happen
     * before the deferred move so we never access components afterward */
    sh2_stream_t *stream =
        nghttp2_session_get_stream_user_data(conn->ng_session, (int32_t)sid->id);
    if (stream) {
      stream->entity        = entity;
      stream->emitted       = true;
      stream->send_complete = !data_prd.read_callback;
      stream->send_data     = data_prd.source.ptr;
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_response_sending),
                "move entity to sending");
    } else {
      /* stream already closed (peer reset, connection teardown, etc.)
       * — move entity straight to result_out so it doesn't leak.
       * Use the SoA array (fetched before any moves) to set io_result. */
      ios[i].error = -1;
      if (data_prd.source.ptr) free(data_prd.source.ptr);
      SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_ids.response_out),
                "move no-stream entity to result_out");
    }
  }
}

/* --------------------------------------------------------------------------
 * Drive all connections that have pending nghttp2 output
 * -------------------------------------------------------------------------- */

void sh2_drive_all_sends(sh2_context_t *ctx) {
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(ctx->shift, ctx->coll_conn_active,
                                &entities, &count);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t uce = entities[i];
    sh2_conn_t *conn = sh2_conn_get(ctx, uce);
    if (!conn || !conn->ng_session)
      continue;

    /* evict idle connections — safety net for zombie sessions */
    if (conn->last_active_ns > 0 &&
        sh2_monotonic_ns() - conn->last_active_ns > SH2_IDLE_TIMEOUT_NS) {
      sh2_conn_close(ctx, uce);
      continue;
    }

    /* drive sessions that want to write, OR sessions that are done
     * (neither want_read nor want_write) — the latter need teardown
     * which happens inside sh2_drive_send after the send loop */
    if (nghttp2_session_want_write(conn->ng_session) ||
        !nghttp2_session_want_read(conn->ng_session)) {
      sh2_drive_send(ctx, uce);
      /* Re-fetch conn since drive_send may have destroyed it */
      conn = sh2_conn_get(ctx, uce);
      if (conn)
        conn->last_active_ns = sh2_monotonic_ns();
    }
  }
}

/* --------------------------------------------------------------------------
 * sh2_poll — main event loop tick
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_poll(sh2_context_t *ctx, uint32_t min_complete) {
  if (!ctx)
    return sh2_error_null;

  ++ctx->poll_count;

  sio_result_t sr = sio_poll(ctx->sio, min_complete);
  if (sr != sio_ok) {
    fprintf(stderr, "[poll #%lu] sio_poll failed: %d\n",
            (unsigned long)ctx->poll_count, sr);
    return sh2_error_io;
  }

  /* PHASE 1: Consume user input.
   * Server: move response_in → response_sending.
   * Client: consume connect/request/cancel/disconnect queues. */
  sh2_consume_responses(ctx);
  sh2_consume_connect_requests(ctx);
  sh2_consume_client_requests(ctx);
  sh2_consume_client_cancels(ctx);
  sh2_consume_client_connect_closes(ctx);
  /* FLUSH: Materialize moves from consume_* (response_in → sending,
   * request_in → client_request_sending, cancel_in → response_out, etc.).
   * After this, entity collection membership reflects user submissions. */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 2: Initialize new client connections and process connect errors. */
  sh2_process_connect_results(ctx);
  sh2_process_connect_errors(ctx);
  /* FLUSH: Materialize connect processing (client conn init, error entity
   * moves to connect_errors, sio error entities destroyed). */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 3: Read triage — sort sio read results by connection state. */
  sh2_reads_triage(ctx);
  /* FLUSH: Materialize triage moves (read entities → error/init/active). */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 4: Handle read errors — close connections, destroy entities. */
  sh2_reads_handle_errors(ctx);
  /* FLUSH: Materialize error-path destroys and connection closes. */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 5: Init new connections (create nghttp2 sessions or start TLS). */
  sh2_reads_init_connections(ctx);
  sh2_reads_init_client_connections(ctx);
  /* FLUSH: Materialize session creation side-effects (component writes)
   * and read entity moves (init → handshake or init → active). */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 6: Transition NEW user_conn entities to active or tls_handshake. */
  sh2_transition_new_connections(ctx);
  /* FLUSH: Materialize user_conn moves (sio_connections → active
   * or → tls_handshake). Required before handshake pass reads them. */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

#ifdef SH2_HAS_TLS
  /* PHASE 7: Drive TLS handshakes (server + client). */
  if (ctx->tls_config) {
    sh2_reads_tls_handshake(ctx);
    /* FLUSH: Materialize handshake entity recycles and any error destroys. */
    SH2_CHECK(shift_flush(ctx->shift), "shift_flush");
  }
  sh2_reads_client_tls_handshake(ctx);
  /* FLUSH: Materialize client handshake entity recycles and destroys. */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 8: Transition completed TLS handshakes → active. */
  sh2_transition_handshake_connections(ctx);
  /* FLUSH: Materialize user_conn moves (tls_handshake → active). */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");
#endif

  /* PHASE 9: Feed active data to nghttp2 (both server and client). */
  sh2_reads_feed_data(ctx);
  /* FLUSH: Materialize read entity recycles and any nghttp2-triggered
   * entity creates/moves from callbacks (stream_emit_request, etc.). */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 10: Account for completed writes, close error connections. */
  sh2_writes_account_and_close(ctx);
  /* FLUSH: Materialize write entity destroys and connection closes. */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 11: Finalize draining connections (pending_writes == 0). */
  sh2_writes_finalize_draining(ctx);
  /* FLUSH: Materialize connection entity destroys. */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* PHASE 12: Drive all nghttp2 output (server + client). */
  sh2_drive_all_sends(ctx);
  /* FLUSH: Materialize send-path entity creates (write_in) and any
   * session teardown moves (active → draining). */
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  return sh2_ok;
}
