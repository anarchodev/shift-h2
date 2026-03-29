#include "sh2_nghttp2.h"
#include "sh2_nghttp2_client.h"
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

    /* new connection needing init — route by direction */
    if (cidx->state == SH2_CONN_NEW) {
      shift_collection_id_t dest = (cidx->direction == SH2_DIR_CLIENT)
          ? ctx->coll_read_client_init : ctx->coll_read_init;
      SH2_CHECK(shift_entity_move_one(sh, entities[i], dest),
                "triage: new → init");
      continue;
    }

#ifdef SH2_HAS_TLS
    /* TLS handshake in progress — route by direction */
    if (cidx->state == SH2_CONN_TLS_HANDSHAKE) {
      shift_collection_id_t dest = (cidx->direction == SH2_DIR_CLIENT)
          ? ctx->coll_read_client_handshake : ctx->coll_read_handshake;
      SH2_CHECK(shift_entity_move_one(sh, entities[i], dest),
                "triage: tls_handshake → handshake");
      continue;
    }
#endif

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

      if (cidx->state == SH2_CONN_ACTIVE
#ifdef SH2_HAS_TLS
          || cidx->state == SH2_CONN_TLS_HANDSHAKE
#endif
         ) {
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

    sh2_conn_t *conn = &ctx->conns[conn_idx];
    *conn = (sh2_conn_t){
        .conn_entity = conns[i].entity,
        .user_conn_entity = user_conn,
        .last_active_poll = ctx->poll_count,
    };

#ifdef SH2_HAS_TLS
    if (ctx->tls_config) {
      /* TLS mode: create SSL object, start handshake */
      if (sh2_tls_conn_create(ctx, conn_idx) != sh2_ok) {
        SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                  "destroy conn_entity (tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                  "destroy user_conn (tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (tls fail)");
        *conn = (sh2_conn_t){0};
        cidx->state = SH2_CONN_NEW;
        continue;
      }
      cidx->state = SH2_CONN_TLS_HANDSHAKE;
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_handshake),
                "init → tls_handshake");
    } else
#endif
    {
      /* h2c mode: create nghttp2 session directly */
      cidx->state = SH2_CONN_ACTIVE;

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
}

#ifdef SH2_HAS_TLS
/* Pass 3.5: Drive TLS handshakes */
static void reads_tls_handshake(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  sio_read_buf_t *rbufs = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_handshake, &entities, &count);
  if (count == 0)
    return;

  shift_collection_get_component_array(sh, ctx->coll_read_handshake,
                                       ctx->sio_comp_ids.read_buf,
                                       (void **)&rbufs, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_handshake,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_conn = uconns[i].entity;

    /* connection already torn down */
    if (shift_entity_is_stale(sh, user_conn) ||
        shift_entity_is_moving(sh, user_conn)) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (handshake stale)");
      continue;
    }

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (tls_handshake)");

    sh2_conn_t *conn = &ctx->conns[cidx->idx];
    sh2_tls_conn_t *tconn = conn->tls;
    if (!tconn) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (no tls)");
      continue;
    }

    /* stack buffer for any decrypted data after handshake completes */
    uint8_t decrypt_buf[65536];
    uint32_t decrypt_len = 0;

    sh2_result_t r = sh2_tls_feed(ctx, cidx->idx,
                                   rbufs[i].data, rbufs[i].len,
                                   decrypt_buf, sizeof(decrypt_buf),
                                   &decrypt_len);

    /* drain handshake output (ServerHello, etc.) to sio write */
    uint32_t wbio_len = 0;
    uint8_t *wbio_data = sh2_tls_drain_wbio(ctx, cidx->idx, &wbio_len);
    if (wbio_data && wbio_len > 0) {
      shift_entity_t we;
      SH2_CHECK(shift_entity_create_one_begin(sh, sio_colls->write_in, &we),
                "create write entity (handshake)");

      sio_write_buf_t *wb = NULL;
      SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.write_buf,
                                            (void **)&wb),
                "get write_buf (handshake)");
      wb->data   = wbio_data;
      wb->len    = wbio_len;
      wb->offset = 0;

      sio_conn_entity_t *ce = NULL;
      SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.conn_entity,
                                            (void **)&ce),
                "get conn_entity (handshake write)");
      ce->entity = conn->conn_entity;

      sio_user_conn_entity_t *uce = NULL;
      SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.user_conn_entity,
                                            (void **)&uce),
                "get user_conn_entity (handshake write)");
      uce->entity = conn->user_conn_entity;

      SH2_CHECK(shift_entity_create_one_end(sh, we), "create_end write entity (handshake)");
      conn->pending_writes++;
    }

    if (r != sh2_ok) {
      /* handshake failed — close connection */
      sh2_conn_close(ctx, cidx->idx);
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (handshake fail)");
      continue;
    }

    if (tconn->handshake_done) {
      /* verify ALPN selected h2 */
      const unsigned char *alpn = NULL;
      unsigned int alpn_len = 0;
      SSL_get0_alpn_selected(tconn->ssl, &alpn, &alpn_len);
      if (alpn_len != 2 || alpn[0] != 'h' || alpn[1] != '2') {
        sh2_conn_close(ctx, cidx->idx);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (no alpn h2)");
        continue;
      }

      /* transition to ACTIVE, create nghttp2 session */
      cidx->state = SH2_CONN_ACTIVE;

      if (sh2_nghttp2_session_create(ctx, cidx->idx) != sh2_ok) {
        sh2_conn_close(ctx, cidx->idx);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (session fail after handshake)");
        continue;
      }

      /* feed any decrypted data from the same segment to nghttp2 */
      if (decrypt_len > 0) {
        nghttp2_ssize consumed =
            nghttp2_session_mem_recv(conn->ng_session, decrypt_buf, decrypt_len);
        if (consumed < 0) {
          sh2_conn_close(ctx, cidx->idx);
          SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                    "destroy read entity (recv error after handshake)");
          continue;
        }
      }

      conn->last_active_poll = ctx->poll_count;

      /* recycle read buffer into active flow */
      SH2_CHECK(shift_entity_move_one(sh, entities[i], sio_colls->read_in),
                "recycle read buffer (handshake done)");
    } else {
      /* handshake needs more data — recycle read buffer */
      conn->last_active_poll = ctx->poll_count;
      SH2_CHECK(shift_entity_move_one(sh, entities[i], sio_colls->read_in),
                "recycle read buffer (handshake continue)");
    }
  }
}
#endif /* SH2_HAS_TLS */

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

#ifdef SH2_HAS_TLS
    if (conn->tls) {
      /* TLS: decrypt raw TCP → plaintext → nghttp2 */
      uint8_t decrypt_buf[65536];
      uint32_t decrypt_len = 0;

      sh2_result_t r = sh2_tls_feed(ctx, cidx->idx,
                                     rbufs[i].data, rbufs[i].len,
                                     decrypt_buf, sizeof(decrypt_buf),
                                     &decrypt_len);
      if (r != sh2_ok) {
        sh2_conn_close(ctx, cidx->idx);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (tls decrypt error)");
        continue;
      }

      if (decrypt_len > 0) {
        nghttp2_ssize consumed =
            nghttp2_session_mem_recv(conn->ng_session, decrypt_buf, decrypt_len);
        if (consumed < 0) {
          sh2_conn_close(ctx, cidx->idx);
          SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                    "destroy read entity (recv error)");
          continue;
        }
      }
    } else
#endif
    {
      /* h2c: feed raw TCP directly to nghttp2 */
      nghttp2_ssize consumed =
          nghttp2_session_mem_recv(conn->ng_session, rbufs[i].data, rbufs[i].len);

      if (consumed < 0) {
        sh2_conn_close(ctx, cidx->idx);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (recv error)");
        continue;
      }
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
    free(conn->hostname);
    *conn = (sh2_conn_t){0};
  }
}

/* --------------------------------------------------------------------------
 * Client: consume connect requests from connect_out
 * -------------------------------------------------------------------------- */

static void consume_connect_requests(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  size_t count = 0;
  shift_collection_get_entities(sh, ctx->coll_ids_client.connect_out,
                                &entities, &count);
  if (count == 0) return;

  sh2_connect_target_t *targets = NULL;
  shift_collection_get_component_array(sh, ctx->coll_ids_client.connect_out,
                                       ctx->comp_ids.connect_target,
                                       (void **)&targets, NULL);

  for (size_t i = 0; i < count; i++) {
    sh2_connect_target_t *tgt = &targets[i];

    /* allocate a connection slot */
    uint32_t conn_idx = UINT32_MAX;
    for (uint32_t j = 0; j < ctx->max_connections; j++) {
      if (!ctx->conns[j].ng_session && !ctx->conns[j].draining
          && !ctx->conns[j].hostname) {
        conn_idx = j;
        break;
      }
    }
    if (conn_idx == UINT32_MAX) {
      /* no room — report error */
      sh2_io_result_t *io = NULL;
      SH2_CHECK(shift_entity_get_component(sh, entities[i], ctx->comp_ids.io_result,
                                            (void **)&io),
                "get io_result (connect no room)");
      io->error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entities[i],
                                       ctx->coll_ids_client.connect_result_out),
                "move connect entity (no room)");
      continue;
    }

    /* store hostname */
    char *hostname = NULL;
    if (tgt->hostname && tgt->hostname_len > 0) {
      hostname = malloc(tgt->hostname_len + 1);
      if (hostname) {
        memcpy(hostname, tgt->hostname, tgt->hostname_len);
        hostname[tgt->hostname_len] = '\0';
      }
    }
    ctx->conns[conn_idx].hostname = hostname;

    /* create sio connect entity */
    shift_entity_t ce;
    SH2_CHECK(shift_entity_create_one_begin(sh, sio_colls->connect_in, &ce),
              "create sio connect entity");

    sio_connect_addr_t *ca = NULL;
    SH2_CHECK(shift_entity_get_component(sh, ce, ctx->sio_comp_ids.connect_addr,
                                          (void **)&ca),
              "get connect_addr");
    ca->addr = tgt->addr;

    SH2_CHECK(shift_entity_create_one_end(sh, ce), "create_end sio connect entity");

    /* destroy the user's connect_out entity — we've consumed it */
    SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
              "destroy connect_out entity");
  }
}

/* --------------------------------------------------------------------------
 * Client: process sio connect results
 * -------------------------------------------------------------------------- */

static void process_connect_results(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;

  shift_entity_t *entities = NULL;
  size_t count = 0;
  shift_collection_get_entities(sh, ctx->sio_connect_results,
                                &entities, &count);
  if (count == 0) return;

  sio_io_result_t *results = NULL;
  sio_conn_entity_t *conns = NULL;
  sio_user_conn_entity_t *uconns = NULL;

  shift_collection_get_component_array(sh, ctx->sio_connect_results,
                                       ctx->sio_comp_ids.io_result,
                                       (void **)&results, NULL);
  shift_collection_get_component_array(sh, ctx->sio_connect_results,
                                       ctx->sio_comp_ids.conn_entity,
                                       (void **)&conns, NULL);
  shift_collection_get_component_array(sh, ctx->sio_connect_results,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    if (results[i].error != 0) {
      /* connect failed — report error to user */
      /* TODO: associate with original conn_idx and report properly */
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy connect result (error)");
      continue;
    }

    /* success: set up the conn_idx on the user_conn entity */
    shift_entity_t user_conn = uconns[i].entity;

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (connect result)");
    cidx->state     = SH2_CONN_NEW;
    cidx->direction = SH2_DIR_CLIENT;

    SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
              "destroy connect result entity");
  }
}

/* --------------------------------------------------------------------------
 * Client: init new client connections (from coll_read_client_init)
 * -------------------------------------------------------------------------- */

static void reads_init_client_connections(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  sio_conn_entity_t *conns = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_client_init, &entities, &count);
  if (count == 0) return;

  shift_collection_get_component_array(sh, ctx->coll_read_client_init,
                                       ctx->sio_comp_ids.conn_entity,
                                       (void **)&conns, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_client_init,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_conn = uconns[i].entity;

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (client init)");

    /* find a free connection slot */
    uint32_t conn_idx = UINT32_MAX;
    for (uint32_t j = 0; j < ctx->max_connections; j++) {
      if (!ctx->conns[j].ng_session && !ctx->conns[j].draining) {
        conn_idx = j;
        break;
      }
    }

    if (conn_idx == UINT32_MAX) {
      SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                "destroy conn_entity (client no room)");
      SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                "destroy user_conn (client no room)");
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (client no room)");
      continue;
    }

    cidx->idx = conn_idx;

    sh2_conn_t *conn = &ctx->conns[conn_idx];
    char *hostname = conn->hostname; /* preserved from consume_connect_requests */
    *conn = (sh2_conn_t){
        .conn_entity      = conns[i].entity,
        .user_conn_entity = user_conn,
        .last_active_poll = ctx->poll_count,
        .hostname         = hostname,
    };

#ifdef SH2_HAS_TLS
    if (ctx->tls_client_config) {
      if (sh2_tls_client_conn_create(ctx, conn_idx, hostname) != sh2_ok) {
        SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                  "destroy conn_entity (client tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                  "destroy user_conn (client tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (client tls fail)");
        free(conn->hostname);
        *conn = (sh2_conn_t){0};
        cidx->state = SH2_CONN_NEW;
        continue;
      }
      cidx->state = SH2_CONN_TLS_HANDSHAKE;

      /* drive initial ClientHello — drain wbio for the first handshake message */
      uint32_t wbio_len = 0;
      uint8_t *wbio_data = sh2_tls_drain_wbio(ctx, conn_idx, &wbio_len);

      /* TLS client needs to initiate handshake by calling SSL_do_handshake */
      uint8_t dummy_decrypt[1];
      uint32_t dummy_len = 0;
      sh2_tls_feed(ctx, conn_idx, NULL, 0, dummy_decrypt, 0, &dummy_len);

      /* drain the ClientHello */
      if (!wbio_data) {
        wbio_data = sh2_tls_drain_wbio(ctx, conn_idx, &wbio_len);
      }
      if (wbio_data && wbio_len > 0) {
        shift_entity_t we;
        SH2_CHECK(shift_entity_create_one_begin(sh, sio_colls->write_in, &we),
                  "create write entity (client hello)");

        sio_write_buf_t *wb = NULL;
        SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.write_buf,
                                              (void **)&wb),
                  "get write_buf (client hello)");
        wb->data   = wbio_data;
        wb->len    = wbio_len;
        wb->offset = 0;

        sio_conn_entity_t *ce = NULL;
        SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.conn_entity,
                                              (void **)&ce),
                  "get conn_entity (client hello)");
        ce->entity = conn->conn_entity;

        sio_user_conn_entity_t *uce = NULL;
        SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.user_conn_entity,
                                              (void **)&uce),
                  "get user_conn_entity (client hello)");
        uce->entity = conn->user_conn_entity;

        SH2_CHECK(shift_entity_create_one_end(sh, we), "create_end write entity (client hello)");
        conn->pending_writes++;
      }

      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_client_handshake),
                "client init → tls_handshake");
    } else
#endif
    {
      cidx->state = SH2_CONN_ACTIVE;

      if (sh2_nghttp2_client_session_create(ctx, conn_idx) != sh2_ok) {
        SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                  "destroy conn_entity (client session fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                  "destroy user_conn (client session fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (client session fail)");
        free(conn->hostname);
        *conn = (sh2_conn_t){0};
        cidx->state = SH2_CONN_NEW;
        continue;
      }

      /* emit connect_result_out — session is ready */
      {
        shift_entity_t re;
        SH2_CHECK(shift_entity_create_one_begin(sh,
                      ctx->coll_ids_client.connect_result_out, &re),
                  "create connect_result entity (h2c)");

        sh2_session_t *sess = NULL;
        SH2_CHECK(shift_entity_get_component(sh, re, ctx->comp_ids.session,
                                              (void **)&sess),
                  "get session (connect_result h2c)");
        sess->entity = conn->user_conn_entity;

        sh2_io_result_t *io = NULL;
        SH2_CHECK(shift_entity_get_component(sh, re, ctx->comp_ids.io_result,
                                              (void **)&io),
                  "get io_result (connect_result h2c)");
        io->error = 0;

        SH2_CHECK(shift_entity_create_end(sh, &re, 1),
                  "create_end connect_result entity (h2c)");
      }

      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_active),
                "client init → active");
    }
  }
}

/* --------------------------------------------------------------------------
 * Client: drive client TLS handshakes (from coll_read_client_handshake)
 * -------------------------------------------------------------------------- */

#ifdef SH2_HAS_TLS
static void reads_client_tls_handshake(sh2_context_t *ctx) {
  if (!ctx->enable_connect || !ctx->tls_client_config) return;

  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  sio_read_buf_t *rbufs = NULL;
  sio_user_conn_entity_t *uconns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_client_handshake,
                                &entities, &count);
  if (count == 0) return;

  shift_collection_get_component_array(sh, ctx->coll_read_client_handshake,
                                       ctx->sio_comp_ids.read_buf,
                                       (void **)&rbufs, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_client_handshake,
                                       ctx->sio_comp_ids.user_conn_entity,
                                       (void **)&uconns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_conn = uconns[i].entity;

    if (shift_entity_is_stale(sh, user_conn) ||
        shift_entity_is_moving(sh, user_conn)) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (client handshake stale)");
      continue;
    }

    sh2_conn_idx_t *cidx = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_conn, ctx->internal_conn_idx,
                                          (void **)&cidx),
              "get conn_idx (client tls_handshake)");

    sh2_conn_t *conn = &ctx->conns[cidx->idx];
    sh2_tls_conn_t *tconn = conn->tls;
    if (!tconn) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (client no tls)");
      continue;
    }

    uint8_t decrypt_buf[65536];
    uint32_t decrypt_len = 0;

    sh2_result_t r = sh2_tls_feed(ctx, cidx->idx,
                                   rbufs[i].data, rbufs[i].len,
                                   decrypt_buf, sizeof(decrypt_buf),
                                   &decrypt_len);

    /* drain handshake output to sio write */
    uint32_t wbio_len = 0;
    uint8_t *wbio_data = sh2_tls_drain_wbio(ctx, cidx->idx, &wbio_len);
    if (wbio_data && wbio_len > 0) {
      shift_entity_t we;
      SH2_CHECK(shift_entity_create_one_begin(sh, sio_colls->write_in, &we),
                "create write entity (client handshake)");

      sio_write_buf_t *wb = NULL;
      SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.write_buf,
                                            (void **)&wb),
                "get write_buf (client handshake)");
      wb->data   = wbio_data;
      wb->len    = wbio_len;
      wb->offset = 0;

      sio_conn_entity_t *ce = NULL;
      SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.conn_entity,
                                            (void **)&ce),
                "get conn_entity (client handshake write)");
      ce->entity = conn->conn_entity;

      sio_user_conn_entity_t *uce = NULL;
      SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.user_conn_entity,
                                            (void **)&uce),
                "get user_conn_entity (client handshake write)");
      uce->entity = conn->user_conn_entity;

      SH2_CHECK(shift_entity_create_one_end(sh, we),
                "create_end write entity (client handshake)");
      conn->pending_writes++;
    }

    if (r != sh2_ok) {
      sh2_conn_close(ctx, cidx->idx);
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (client handshake fail)");
      continue;
    }

    if (tconn->handshake_done) {
      /* verify ALPN selected h2 */
      const unsigned char *alpn = NULL;
      unsigned int alpn_len = 0;
      SSL_get0_alpn_selected(tconn->ssl, &alpn, &alpn_len);
      if (alpn_len != 2 || alpn[0] != 'h' || alpn[1] != '2') {
        sh2_conn_close(ctx, cidx->idx);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (client no alpn h2)");
        continue;
      }

      cidx->state = SH2_CONN_ACTIVE;

      if (sh2_nghttp2_client_session_create(ctx, cidx->idx) != sh2_ok) {
        sh2_conn_close(ctx, cidx->idx);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (client session fail after handshake)");
        continue;
      }

      /* feed any decrypted data from same segment to nghttp2 */
      if (decrypt_len > 0) {
        nghttp2_ssize consumed =
            nghttp2_session_mem_recv(conn->ng_session, decrypt_buf, decrypt_len);
        if (consumed < 0) {
          sh2_conn_close(ctx, cidx->idx);
          SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                    "destroy read entity (client recv error after handshake)");
          continue;
        }
      }

      conn->last_active_poll = ctx->poll_count;

      /* emit connect_result_out — session is ready */
      {
        shift_entity_t re;
        SH2_CHECK(shift_entity_create_one_begin(sh,
                      ctx->coll_ids_client.connect_result_out, &re),
                  "create connect_result entity");

        sh2_session_t *sess = NULL;
        SH2_CHECK(shift_entity_get_component(sh, re, ctx->comp_ids.session,
                                              (void **)&sess),
                  "get session (connect_result)");
        sess->entity = conn->user_conn_entity;

        sh2_io_result_t *io = NULL;
        SH2_CHECK(shift_entity_get_component(sh, re, ctx->comp_ids.io_result,
                                              (void **)&io),
                  "get io_result (connect_result)");
        io->error = 0;

        SH2_CHECK(shift_entity_create_end(sh, &re, 1),
                  "create_end connect_result entity");
      }

      SH2_CHECK(shift_entity_move_one(sh, entities[i], sio_colls->read_in),
                "recycle read buffer (client handshake done)");
    } else {
      conn->last_active_poll = ctx->poll_count;
      SH2_CHECK(shift_entity_move_one(sh, entities[i], sio_colls->read_in),
                "recycle read buffer (client handshake continue)");
    }
  }
}
#endif /* SH2_HAS_TLS */

/* --------------------------------------------------------------------------
 * Client: consume client_request_in — submit requests to nghttp2
 * -------------------------------------------------------------------------- */

static void consume_client_requests(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  shift_collection_id_t coll = ctx->coll_ids_client.request_in;
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, coll, &entities, &count);
  if (count == 0) return;

  sh2_session_t *sessions = NULL;
  sh2_req_headers_t *rhs = NULL;
  sh2_req_body_t *rbs = NULL;
  sh2_io_result_t *ios = NULL;

  shift_collection_get_component_array(sh, coll, ctx->comp_ids.session,
                                       (void **)&sessions, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.req_headers,
                                       (void **)&rhs, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.req_body,
                                       (void **)&rbs, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.io_result,
                                       (void **)&ios, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t entity = entities[i];
    sh2_session_t *sess = &sessions[i];
    sh2_req_headers_t *rh = &rhs[i];
    sh2_req_body_t *rb = &rbs[i];

    /* find connection */
    if (shift_entity_is_stale(sh, sess->entity)) {
      ios[i].error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity,
                    ctx->coll_ids_client.response_result_out),
                "move stale client request to result_out");
      continue;
    }

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
      SH2_CHECK(shift_entity_move_one(sh, entity,
                    ctx->coll_ids_client.response_result_out),
                "move orphan client request to result_out");
      continue;
    }

    sh2_conn_t *conn = &ctx->conns[conn_idx];

    /* build nghttp2_nv array from req_headers */
    uint32_t nv_count = rh->count;
    nghttp2_nv *nva = malloc(nv_count * sizeof(nghttp2_nv));
    if (!nva) continue;

    for (uint32_t j = 0; j < rh->count; j++) {
      nva[j] = (nghttp2_nv){
          .name     = (uint8_t *)rh->fields[j].name,
          .namelen  = rh->fields[j].name_len,
          .value    = (uint8_t *)rh->fields[j].value,
          .valuelen = rh->fields[j].value_len,
          .flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME |
                      NGHTTP2_NV_FLAG_NO_COPY_VALUE,
      };
    }

    /* data provider for request body */
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

    int32_t stream_id = nghttp2_submit_request(
        conn->ng_session, NULL, nva, nv_count,
        data_prd.read_callback ? &data_prd : NULL, NULL);
    free(nva);

    if (stream_id < 0) {
      ios[i].error = -1;
      if (data_prd.source.ptr) free(data_prd.source.ptr);
      SH2_CHECK(shift_entity_move_one(sh, entity,
                    ctx->coll_ids_client.response_result_out),
                "move failed client request to result_out");
      continue;
    }

    /* move to internal sending collection */
    SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_client_request_sending),
              "move client request to sending");

    /* associate entity with the stream */
    sh2_stream_t *stream =
        nghttp2_session_get_stream_user_data(conn->ng_session, stream_id);
    if (stream) {
      stream->entity        = entity;
      stream->emitted       = false;
      stream->send_complete = !data_prd.read_callback;
    }
  }
}

/* --------------------------------------------------------------------------
 * sh2_poll
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

  /* server: consume responses queued by user */
  consume_responses(ctx);
  /* client: consume connect requests and client requests */
  consume_connect_requests(ctx);
  consume_client_requests(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* client: process sio connect results */
  process_connect_results(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* read pass 1: triage into errors / init / active (direction-aware) */
  reads_triage(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* read pass 2: handle errors — close connections, destroy entities */
  reads_handle_errors(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* read pass 3: init new server connections */
  reads_init_connections(ctx);
  /* read pass 3b: init new client connections */
  reads_init_client_connections(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

#ifdef SH2_HAS_TLS
  /* read pass 3.5: drive server TLS handshakes */
  if (ctx->tls_config) {
    reads_tls_handshake(ctx);
    SH2_CHECK(shift_flush(ctx->shift), "shift_flush");
  }
  /* read pass 3.5b: drive client TLS handshakes */
  reads_client_tls_handshake(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");
#endif

  /* read pass 4: feed active data to nghttp2 (direction-agnostic) */
  reads_feed_data(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* write pass 1: free data, decrement counters, close error connections */
  writes_account_and_close(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* write pass 2: finalize draining connections */
  writes_finalize_draining(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* second pass for responses/requests queued during this tick */
  consume_responses(ctx);
  consume_client_requests(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  /* drive all nghttp2 output (direction-agnostic) */
  drive_all_sends(ctx);
  SH2_CHECK(shift_flush(ctx->shift), "shift_flush");

  return sh2_ok;
}
