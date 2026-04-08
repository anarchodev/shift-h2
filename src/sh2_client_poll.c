#include "sh2_poll_internal.h"
#include "sh2_nghttp2.h"
#include "sh2_nghttp2_client.h"

#ifdef SH2_HAS_TLS
#include "sh2_tls.h"
#endif

#include <string.h>

/* --------------------------------------------------------------------------
 * Client: consume connect requests from connect_in
 * -------------------------------------------------------------------------- */

void sh2_consume_connect_requests(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  size_t count = 0;
  shift_collection_get_entities(sh, ctx->coll_ids_client.connect_in,
                                &entities, &count);
  if (count == 0) return;

  sh2_connect_target_t *targets = NULL;
  shift_collection_get_component_array(sh, ctx->coll_ids_client.connect_in,
                                       ctx->comp_ids.connect_target,
                                       (void **)&targets, NULL);

  for (size_t i = 0; i < count; i++) {
    sh2_connect_target_t *tgt = &targets[i];

    /* create sio connect entity — hostname travels with it through sio */
    shift_entity_t ce;
    SH2_CHECK(shift_entity_create_one_begin(sh, sio_colls->connect_in, &ce),
              "create sio connect entity");

    sio_connect_addr_t *ca = NULL;
    SH2_CHECK(shift_entity_get_component(sh, ce, ctx->sio_comp_ids.connect_addr,
                                          (void **)&ca),
              "get connect_addr");
    ca->addr = tgt->addr;

    /* store hostname on the connect entity so it round-trips through sio */
    sh2_hostname_t *hn = NULL;
    SH2_CHECK(shift_entity_get_component(sh, ce, ctx->internal_hostname,
                                          (void **)&hn),
              "get hostname (connect)");
    if (tgt->hostname && tgt->hostname_len > 0) {
      hn->hostname = malloc(tgt->hostname_len + 1);
      if (hn->hostname) {
        memcpy(hn->hostname, tgt->hostname, tgt->hostname_len);
        hn->hostname[tgt->hostname_len] = '\0';
      }
    }

    /* store user entity handle on sio connect entity so we can
     * correlate it back when sio returns the connect result */
    sh2_connect_entity_t *connect_ent = NULL;
    SH2_CHECK(shift_entity_get_component(sh, ce, ctx->internal_connect_entity,
                                          (void **)&connect_ent),
              "get connect_entity (connect)");
    connect_ent->entity = entities[i];

    /* mark as client connection — survives through sio's pipeline */
    sh2_conn_t *conn = NULL;
    SH2_CHECK(shift_entity_get_component(sh, ce, ctx->internal_conn,
                                          (void **)&conn),
              "get internal_conn (connect)");
    conn->direction = SH2_DIR_CLIENT;

    SH2_CHECK(shift_entity_create_one_end(sh, ce), "create_end sio connect entity");

    /* park user entity — same entity will appear in connect_out */
    SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_connect_pending),
              "move connect_in → connect_pending");
  }
}

/* --------------------------------------------------------------------------
 * Client: initialize new client connections in sio_connections
 *
 * After sio completes a connect, the entity moves to sio_connections.
 * We identify client connections by internal_connect_entity being set
 * (accepted connections have it zeroed).  Initialize sh2_conn_t and
 * transfer hostname.
 * -------------------------------------------------------------------------- */

void sh2_process_connect_results(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;

  shift_entity_t *entities = NULL;
  size_t count = 0;
  shift_collection_get_entities(sh, ctx->sio_connections,
                                &entities, &count);
  if (count == 0) return;

  sh2_conn_t *conns_arr = NULL;
  sh2_connect_entity_t *user_entities = NULL;
  sh2_hostname_t *hostnames = NULL;

  shift_collection_get_component_array(sh, ctx->sio_connections,
                                       ctx->internal_conn,
                                       (void **)&conns_arr, NULL);
  shift_collection_get_component_array(sh, ctx->sio_connections,
                                       ctx->internal_connect_entity,
                                       (void **)&user_entities, NULL);
  shift_collection_get_component_array(sh, ctx->sio_connections,
                                       ctx->internal_hostname,
                                       (void **)&hostnames, NULL);

  for (size_t i = 0; i < count; i++) {
    /* skip server connections and already-initialized clients */
    if (conns_arr[i].direction != SH2_DIR_CLIENT || conns_arr[i].last_active_ns != 0)
      continue;

    shift_entity_t user_ent = user_entities[i].entity;
    shift_entity_t conn_ent = entities[i];
    sh2_conn_t *conn = &conns_arr[i];
    conn->last_active_ns      = sh2_monotonic_ns();
    conn->pending_user_entity = user_ent;

    /* Transfer hostname from component to conn struct */
    conn->hostname = hostnames[i].hostname;
    hostnames[i].hostname = NULL;

#ifdef SH2_HAS_TLS
    if (ctx->tls_client_config) {
      /* TLS: session created later in reads_init_client_connections after
       * handshake.  Nothing more to do here. */
    } else
#endif
    {
      /* h2c: create nghttp2 session immediately — it needs to send the
       * client connection preface before any data can arrive. */
      if (sh2_nghttp2_client_session_create(ctx, conn_ent) != sh2_ok) {
        sh2_io_result_t *io = NULL;
        SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                              (void **)&io),
                  "get io_result (connect session fail)");
        io->error = -1;
        SH2_CHECK(shift_entity_move_one(sh, user_ent,
                      ctx->coll_ids_client.connect_errors),
                  "move connect_pending → connect_errors (session fail)");
        continue;
      }

      /* emit connect_out — move user's original entity */
      sh2_session_t *sess = NULL;
      SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.session,
                                            (void **)&sess),
                "get session (connect_result h2c)");
      sess->entity = conn_ent;
      SH2_CHECK(shift_entity_move_one(sh, user_ent,
                    ctx->coll_ids_client.connect_out),
                "move connect_pending → connect_out (h2c)");
    }
  }
}

/* --------------------------------------------------------------------------
 * Client: process sio connect errors
 *
 * Failed connects land in sio_connect_errors.  Retrieve the user's
 * original entity and move it to connect_errors with the error code.
 * -------------------------------------------------------------------------- */

void sh2_process_connect_errors(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;

  shift_entity_t *entities = NULL;
  size_t count = 0;
  shift_collection_get_entities(sh, ctx->sio_connect_errors,
                                &entities, &count);
  if (count == 0) return;

  sio_io_result_t *results = NULL;
  sh2_connect_entity_t *user_entities = NULL;

  shift_collection_get_component_array(sh, ctx->sio_connect_errors,
                                       ctx->sio_comp_ids.io_result,
                                       (void **)&results, NULL);
  shift_collection_get_component_array(sh, ctx->sio_connect_errors,
                                       ctx->internal_connect_entity,
                                       (void **)&user_entities, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t user_ent = user_entities[i].entity;

    sh2_io_result_t *io = NULL;
    SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                          (void **)&io),
              "get io_result (connect error)");
    io->error = results[i].error;
    SH2_CHECK(shift_entity_move_one(sh, user_ent,
                  ctx->coll_ids_client.connect_errors),
              "move connect_pending → connect_errors");
    SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
              "destroy sio connect error entity");
  }
}

/* --------------------------------------------------------------------------
 * Client: init new client connections (from coll_read_client_init)
 * -------------------------------------------------------------------------- */

void sh2_reads_init_client_connections(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  sio_conn_entity_t *conns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_client_init, &entities, &count);
  if (count == 0) return;

  shift_collection_get_component_array(sh, ctx->coll_read_client_init,
                                       ctx->sio_comp_ids.conn_entity,
                                       (void **)&conns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t conn_ent = conns[i].entity;

    sh2_conn_t *conn = sh2_conn_get(ctx, conn_ent);
    if (!conn) {
      SH2_CHECK(shift_entity_destroy_one(sh, conn_ent),
                "destroy conn_entity (client no conn)");
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (client no conn)");
      continue;
    }

    shift_entity_t user_ent = conn->pending_user_entity;
    char *hostname = conn->hostname;

    conn->last_active_ns = sh2_monotonic_ns();

#ifdef SH2_HAS_TLS
    if (ctx->tls_client_config) {
      if (sh2_tls_client_conn_create(ctx, conn, hostname) != sh2_ok) {
        sh2_io_result_t *io = NULL;
        SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                              (void **)&io),
                  "get io_result (client tls fail)");
        io->error = -1;
        SH2_CHECK(shift_entity_move_one(sh, user_ent,
                      ctx->coll_ids_client.connect_out),
                  "move connect_pending → connect_out (client tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, conn_ent),
                  "destroy conn_entity (client tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (client tls fail)");
        continue;
      }
      /* drive initial ClientHello — drain wbio for the first handshake message */
      uint32_t wbio_len = 0;
      uint8_t *wbio_data = sh2_tls_drain_wbio(conn, &wbio_len);

      /* TLS client needs to initiate handshake by calling SSL_do_handshake */
      uint8_t dummy_decrypt[1];
      uint32_t dummy_len = 0;
      sh2_tls_feed(conn, NULL, 0, dummy_decrypt, 0, &dummy_len);

      /* drain the ClientHello */
      if (!wbio_data) {
        wbio_data = sh2_tls_drain_wbio(conn, &wbio_len);
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
        ce->entity = conn_ent;

        SH2_CHECK(shift_entity_create_one_end(sh, we), "create_end write entity (client hello)");
        conn->pending_writes++;
      }

      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_client_handshake),
                "client init → tls_handshake");
    } else
#endif
    {
      if (sh2_nghttp2_client_session_create(ctx, conn_ent) != sh2_ok) {
        sh2_io_result_t *io = NULL;
        SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                              (void **)&io),
                  "get io_result (client session fail)");
        io->error = -1;
        SH2_CHECK(shift_entity_move_one(sh, user_ent,
                      ctx->coll_ids_client.connect_out),
                  "move connect_pending → connect_out (client session fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, conn_ent),
                  "destroy conn_entity (client session fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (client session fail)");
        continue;
      }

      /* emit connect_out — move user's original entity */
      {
        sh2_session_t *sess = NULL;
        SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.session,
                                              (void **)&sess),
                  "get session (connect_result h2c init)");
        sess->entity = conn_ent;

        sh2_io_result_t *io = NULL;
        SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                              (void **)&io),
                  "get io_result (connect_result h2c init)");
        io->error = 0;

        SH2_CHECK(shift_entity_move_one(sh, user_ent,
                      ctx->coll_ids_client.connect_out),
                  "move connect_pending → connect_out (h2c init)");
      }

      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_active),
                "client init → active");
    }
  }
}

#ifdef SH2_HAS_TLS
/* --------------------------------------------------------------------------
 * Client: drive client TLS handshakes (from coll_read_client_handshake)
 * -------------------------------------------------------------------------- */

void sh2_reads_client_tls_handshake(sh2_context_t *ctx) {
  if (!ctx->enable_connect || !ctx->tls_client_config) return;

  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  shift_entity_t *entities = NULL;
  sio_read_buf_t *rbufs = NULL;
  sio_conn_entity_t *conns = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, ctx->coll_read_client_handshake,
                                &entities, &count);
  if (count == 0) return;

  shift_collection_get_component_array(sh, ctx->coll_read_client_handshake,
                                       ctx->sio_comp_ids.read_buf,
                                       (void **)&rbufs, NULL);
  shift_collection_get_component_array(sh, ctx->coll_read_client_handshake,
                                       ctx->sio_comp_ids.conn_entity,
                                       (void **)&conns, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t conn_ent = conns[i].entity;
    uint8_t decrypt_buf[65536];
    uint32_t decrypt_len = 0;

    sh2_hs_step_t step = sh2_tls_handshake_step(
        ctx, entities[i], conn_ent,
        rbufs[i].data, rbufs[i].len,
        decrypt_buf, sizeof(decrypt_buf), &decrypt_len);

    if (step != SH2_HS_DONE)
      continue;

    /* handshake complete — create client nghttp2 session */
    sh2_conn_t *conn = sh2_conn_get(ctx, conn_ent);
    if (!conn) { continue; }

    shift_entity_t user_ent = conn->pending_user_entity;

    if (sh2_nghttp2_client_session_create(ctx, conn_ent) != sh2_ok) {
      sh2_io_result_t *io = NULL;
      SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                            (void **)&io),
                "get io_result (client session fail after handshake)");
      io->error = -1;
      SH2_CHECK(shift_entity_move_one(sh, user_ent,
                    ctx->coll_ids_client.connect_out),
                "move connect_pending → connect_out (session fail after hs)");
      sh2_conn_close(ctx, conn_ent);
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (client session fail after handshake)");
      continue;
    }

    conn = sh2_conn_get(ctx, conn_ent);
    if (!conn) { continue; }

    /* feed any decrypted data from same segment to nghttp2 */
    if (decrypt_len > 0) {
      nghttp2_ssize consumed =
          nghttp2_session_mem_recv(conn->ng_session, decrypt_buf, decrypt_len);
      if (consumed < 0) {
        sh2_io_result_t *io = NULL;
        SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                              (void **)&io),
                  "get io_result (client recv error after handshake)");
        io->error = -1;
        SH2_CHECK(shift_entity_move_one(sh, user_ent,
                      ctx->coll_ids_client.connect_out),
                  "move connect_pending → connect_out (recv error after hs)");
        sh2_conn_close(ctx, conn_ent);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (client recv error after handshake)");
        continue;
      }
    }

    conn->last_active_ns = sh2_monotonic_ns();

    /* emit connect_out — move user's original entity */
    {
      sh2_session_t *sess = NULL;
      SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.session,
                                            (void **)&sess),
                "get session (connect_result tls)");
      sess->entity = conn_ent;

      sh2_io_result_t *io = NULL;
      SH2_CHECK(shift_entity_get_component(sh, user_ent, ctx->comp_ids.io_result,
                                            (void **)&io),
                "get io_result (connect_result tls)");
      io->error = 0;

      SH2_CHECK(shift_entity_move_one(sh, user_ent,
                    ctx->coll_ids_client.connect_out),
                "move connect_pending → connect_out (tls)");
    }

    SH2_CHECK(shift_entity_move_one(sh, entities[i], sio_colls->read_in),
              "recycle read buffer (client handshake done)");
  }
}
#endif /* SH2_HAS_TLS */

/* --------------------------------------------------------------------------
 * Client: consume client_request_in — submit requests to nghttp2
 * -------------------------------------------------------------------------- */

void sh2_consume_client_requests(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  shift_collection_id_t coll = ctx->coll_ids_client.request_in;
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, coll, &entities, &count);
  if (count == 0) return;

  sh2_session_t *sessions = NULL;
  sh2_stream_id_t *sids = NULL;
  sh2_req_headers_t *rhs = NULL;
  sh2_req_body_t *rbs = NULL;
  sh2_io_result_t *ios = NULL;

  shift_collection_get_component_array(sh, coll, ctx->comp_ids.session,
                                       (void **)&sessions, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.stream_id,
                                       (void **)&sids, NULL);
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

    /* find connection via internal_conn component on session entity */
    sh2_conn_t *conn = NULL;
    if (shift_entity_is_stale(sh, sess->entity) ||
        !(conn = sh2_conn_get(ctx, sess->entity))) {
      ios[i].error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity,
                    ctx->coll_ids_client.response_out),
                "move stale/orphan client request to result_out");
      continue;
    }

    /* build nghttp2_nv array from req_headers */
    uint32_t nv_count = rh->count;
    nghttp2_nv *nva = malloc(nv_count * sizeof(nghttp2_nv));
    if (!nva) {
      ios[i].error = -1;
      SH2_CHECK(shift_entity_move_one(sh, entity,
                    ctx->coll_ids_client.response_out),
                "move OOM client request to result_out");
      continue;
    }

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
      sh2_body_data_t *rd = sh2_body_data_alloc(rb->data, rb->len);
      if (!rd) {
        free(nva);
        ios[i].error = -1;
        SH2_CHECK(shift_entity_move_one(sh, entity,
                      ctx->coll_ids_client.response_out),
                  "move body-OOM client request to result_out");
        continue;
      }
      data_prd.source.ptr    = rd;
      data_prd.read_callback = on_data_source_read;
    }

    int32_t stream_id = nghttp2_submit_request(
        conn->ng_session, NULL, nva, nv_count,
        data_prd.read_callback ? &data_prd : NULL, NULL);
    free(nva);

    if (stream_id < 0) {
      ios[i].error = -1;
      if (data_prd.source.ptr) free(data_prd.source.ptr);
      SH2_CHECK(shift_entity_move_one(sh, entity,
                    ctx->coll_ids_client.response_out),
                "move failed client request to result_out");
      continue;
    }

    /* record stream_id on the entity */
    sids[i].id = (uint32_t)stream_id;

    /* allocate stream and associate entity + nghttp2 stream user data —
     * must happen before the deferred move (moves last) */
    sh2_stream_t *stream = sh2_stream_alloc(sess->entity);
    if (!stream) {
      ios[i].error = -1;
      if (data_prd.source.ptr) free(data_prd.source.ptr);
      nghttp2_submit_rst_stream(conn->ng_session, NGHTTP2_FLAG_NONE,
                                stream_id, NGHTTP2_INTERNAL_ERROR);
      SH2_CHECK(shift_entity_move_one(sh, entity,
                    ctx->coll_ids_client.response_out),
                "move OOM client request to result_out");
      continue;
    }
    stream->entity        = entity;
    stream->send_complete = !data_prd.read_callback;
    stream->send_data     = data_prd.source.ptr;
    nghttp2_session_set_stream_user_data(conn->ng_session, stream_id, stream);

    SH2_CHECK(shift_entity_move_one(sh, entity, ctx->coll_client_request_sending),
              "move client request to sending");
  }
}

/* --------------------------------------------------------------------------
 * Client: consume disconnect_in — send GOAWAY for graceful shutdown
 * -------------------------------------------------------------------------- */

void sh2_consume_client_connect_closes(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  shift_collection_id_t coll = ctx->coll_ids_client.disconnect_in;
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, coll, &entities, &count);
  if (count == 0) return;

  sh2_session_t *sessions = NULL;
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.session,
                                       (void **)&sessions, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t entity = entities[i];
    sh2_session_t *sess = &sessions[i];

    /* find connection via internal_conn component on session entity */
    sh2_conn_t *conn = NULL;
    if (!shift_entity_is_stale(sh, sess->entity))
      conn = sh2_conn_get(ctx, sess->entity);

    if (conn && conn->ng_session) {
      int32_t last_stream_id =
          nghttp2_session_get_last_proc_stream_id(conn->ng_session);
      nghttp2_submit_goaway(conn->ng_session, NGHTTP2_FLAG_NONE,
                            last_stream_id, NGHTTP2_NO_ERROR, NULL, 0);
    }

    SH2_CHECK(shift_entity_destroy_one(sh, entity),
              "destroy disconnect_in entity");
  }
}

/* --------------------------------------------------------------------------
 * Client: consume cancel_in — send RST_STREAM for cancelled requests
 * -------------------------------------------------------------------------- */

void sh2_consume_client_cancels(sh2_context_t *ctx) {
  if (!ctx->enable_connect) return;

  shift_t *sh = ctx->shift;
  shift_collection_id_t coll = ctx->coll_ids_client.cancel_in;
  shift_entity_t *entities = NULL;
  size_t count = 0;

  shift_collection_get_entities(sh, coll, &entities, &count);
  if (count == 0) return;

  sh2_stream_id_t *sids = NULL;
  sh2_session_t *sessions = NULL;
  sh2_io_result_t *ios = NULL;

  shift_collection_get_component_array(sh, coll, ctx->comp_ids.stream_id,
                                       (void **)&sids, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.session,
                                       (void **)&sessions, NULL);
  shift_collection_get_component_array(sh, coll, ctx->comp_ids.io_result,
                                       (void **)&ios, NULL);

  for (size_t i = 0; i < count; i++) {
    shift_entity_t entity = entities[i];
    sh2_session_t *sess = &sessions[i];
    uint32_t sid = sids[i].id;

    /* find connection via internal_conn component on session entity */
    sh2_conn_t *conn = NULL;
    if (!shift_entity_is_stale(sh, sess->entity))
      conn = sh2_conn_get(ctx, sess->entity);

    /* submit RST_STREAM if connection is alive */
    if (conn && conn->ng_session && sid != 0) {
      nghttp2_submit_rst_stream(conn->ng_session,
                                NGHTTP2_FLAG_NONE, (int32_t)sid,
                                NGHTTP2_CANCEL);
    }

    ios[i].error = -1;
    SH2_CHECK(shift_entity_move_one(sh, entity,
                  ctx->coll_ids_client.response_out),
              "move cancelled request to result_out");
  }
}
