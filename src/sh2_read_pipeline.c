#include "sh2_poll_internal.h"
#include "sh2_nghttp2.h"
#include "sh2_nghttp2_client.h"

#ifdef SH2_HAS_TLS
#include "sh2_tls.h"
#endif

#include <string.h>

/* --------------------------------------------------------------------------
 * Pass 1: Triage — sort read results into errors, new-conn, or active
 * -------------------------------------------------------------------------- */

void sh2_reads_triage(sh2_context_t *ctx) {
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

    /* determine connection state via collection membership */
    shift_collection_id_t conn_coll = 0;
    if (shift_entity_get_collection(sh, user_conn, &conn_coll) != shift_ok) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_errors),
                "triage: no collection → errors");
      continue;
    }

    /* error, EOF, or connection in draining/unknown state */
    if (results[i].error != 0 || rbufs[i].len == 0 ||
        conn_coll == ctx->coll_conn_draining) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_errors),
                "triage: error/EOF → errors");
      continue;
    }

    /* new connection needing init — still in sio_connection_results */
    if (conn_coll == ctx->sio_connection_results) {
      sh2_conn_t *conn = sh2_conn_get(ctx, user_conn);
      shift_collection_id_t dest = (conn && conn->direction == SH2_DIR_CLIENT)
          ? ctx->coll_read_client_init : ctx->coll_read_init;
      SH2_CHECK(shift_entity_move_one(sh, entities[i], dest),
                "triage: new → init");
      continue;
    }

#ifdef SH2_HAS_TLS
    /* TLS handshake in progress */
    if (conn_coll == ctx->coll_conn_tls_handshake) {
      sh2_conn_t *conn = sh2_conn_get(ctx, user_conn);
      shift_collection_id_t dest = (conn && conn->direction == SH2_DIR_CLIENT)
          ? ctx->coll_read_client_handshake : ctx->coll_read_handshake;
      SH2_CHECK(shift_entity_move_one(sh, entities[i], dest),
                "triage: tls_handshake → handshake");
      continue;
    }
#endif

    /* active connection with data */
    if (conn_coll == ctx->coll_conn_active) {
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_active),
                "triage: active → active");
    } else {
      /* unknown state — treat as error */
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_errors),
                "triage: unknown → errors");
    }
  }
}

/* --------------------------------------------------------------------------
 * Pass 2: Handle errors — close connections, destroy read entities
 * -------------------------------------------------------------------------- */

void sh2_reads_handle_errors(sh2_context_t *ctx) {
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
      shift_collection_id_t conn_coll = 0;
      shift_entity_get_collection(sh, user_conn, &conn_coll);

      if (conn_coll == ctx->coll_conn_active
#ifdef SH2_HAS_TLS
          || conn_coll == ctx->coll_conn_tls_handshake
#endif
         ) {
        sh2_conn_close(ctx, user_conn);
      } else if (conn_coll == ctx->sio_connection_results) {
        /* NEW connection — destroy both entities */
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

/* --------------------------------------------------------------------------
 * Pass 3: Init new server connections
 * -------------------------------------------------------------------------- */

void sh2_reads_init_connections(sh2_context_t *ctx) {
  shift_t *sh = ctx->shift;

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

    sh2_conn_t *conn = sh2_conn_get(ctx, user_conn);
    if (!conn) {
      SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                "destroy conn_entity (no conn)");
      SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                "destroy user_conn (no conn)");
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (no conn)");
      continue;
    }

    /* Initialize connection state on the component */
    conn->conn_entity = conns[i].entity;
    conn->last_active_poll = ctx->poll_count;

#ifdef SH2_HAS_TLS
    if (ctx->tls_config) {
      /* TLS mode: create SSL object, start handshake */
      if (sh2_tls_conn_create(ctx, conn) != sh2_ok) {
        SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                  "destroy conn_entity (tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                  "destroy user_conn (tls fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (tls fail)");
        continue;
      }
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_handshake),
                "init → tls_handshake");
    } else
#endif
    {
      /* h2c mode: create nghttp2 session directly */
      if (sh2_nghttp2_session_create(ctx, user_conn) != sh2_ok) {
        SH2_CHECK(shift_entity_destroy_one(sh, conns[i].entity),
                  "destroy conn_entity (session fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, user_conn),
                  "destroy user_conn (session fail)");
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (session fail)");
        continue;
      }

      /* move to active for data feeding */
      SH2_CHECK(shift_entity_move_one(sh, entities[i], ctx->coll_read_active),
                "init → active");
    }
  }
}

#ifdef SH2_HAS_TLS
/* --------------------------------------------------------------------------
 * Shared TLS handshake step — used by both server and client paths
 * -------------------------------------------------------------------------- */

sh2_hs_step_t sh2_tls_handshake_step(
    sh2_context_t *ctx,
    shift_entity_t read_entity,
    shift_entity_t user_conn,
    const uint8_t *raw_data, uint32_t raw_len,
    uint8_t *decrypt_buf, uint32_t decrypt_cap, uint32_t *decrypt_len) {

  shift_t *sh = ctx->shift;
  const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

  /* connection already torn down */
  if (shift_entity_is_stale(sh, user_conn) ||
      shift_entity_is_moving(sh, user_conn)) {
    SH2_CHECK(shift_entity_destroy_one(sh, read_entity),
              "destroy read entity (handshake stale)");
    return SH2_HS_HANDLED;
  }

  sh2_conn_t *conn = sh2_conn_get(ctx, user_conn);
  if (!conn || !conn->tls) {
    SH2_CHECK(shift_entity_destroy_one(sh, read_entity),
              "destroy read entity (no tls)");
    return SH2_HS_HANDLED;
  }

  *decrypt_len = 0;
  sh2_tls_feed_result_t r = sh2_tls_feed(conn,
                                          raw_data, raw_len,
                                          decrypt_buf, decrypt_cap,
                                          decrypt_len);

  /* drain handshake output to sio write */
  uint32_t wbio_len = 0;
  uint8_t *wbio_data = sh2_tls_drain_wbio(conn, &wbio_len);
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
    uce->entity = user_conn;

    SH2_CHECK(shift_entity_create_one_end(sh, we), "create_end write entity (handshake)");
    conn->pending_writes++;
  }

  if (r == SH2_TLS_ERROR) {
    sh2_conn_close(ctx, user_conn);
    SH2_CHECK(shift_entity_destroy_one(sh, read_entity),
              "destroy read entity (handshake fail)");
    return SH2_HS_HANDLED;
  }

  if (r == SH2_TLS_HANDSHAKE_DONE) {
    /* verify ALPN selected h2 */
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(conn->tls->ssl, &alpn, &alpn_len);
    if (alpn_len != 2 || alpn[0] != 'h' || alpn[1] != '2') {
      sh2_conn_close(ctx, user_conn);
      SH2_CHECK(shift_entity_destroy_one(sh, read_entity),
                "destroy read entity (no alpn h2)");
      return SH2_HS_HANDLED;
    }
    return SH2_HS_DONE;
  }

  /* handshake needs more data — recycle read buffer */
  conn->last_active_poll = ctx->poll_count;
  SH2_CHECK(shift_entity_move_one(sh, read_entity, sio_colls->read_in),
            "recycle read buffer (handshake continue)");
  return SH2_HS_CONTINUE;
}

/* --------------------------------------------------------------------------
 * Pass 3.5: Drive server TLS handshakes
 * -------------------------------------------------------------------------- */

void sh2_reads_tls_handshake(sh2_context_t *ctx) {
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
    uint8_t decrypt_buf[65536];
    uint32_t decrypt_len = 0;

    sh2_hs_step_t step = sh2_tls_handshake_step(
        ctx, entities[i], user_conn,
        rbufs[i].data, rbufs[i].len,
        decrypt_buf, sizeof(decrypt_buf), &decrypt_len);

    if (step != SH2_HS_DONE)
      continue;

    /* handshake complete — create server nghttp2 session */
    sh2_conn_t *conn = sh2_conn_get(ctx, user_conn);
    if (!conn) { continue; }

    if (sh2_nghttp2_session_create(ctx, user_conn) != sh2_ok) {
      sh2_conn_close(ctx, user_conn);
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (session fail after handshake)");
      continue;
    }

    conn = sh2_conn_get(ctx, user_conn);
    if (!conn) { continue; }

    /* feed any decrypted data from the same segment to nghttp2 */
    if (decrypt_len > 0) {
      nghttp2_ssize consumed =
          nghttp2_session_mem_recv(conn->ng_session, decrypt_buf, decrypt_len);
      if (consumed < 0) {
        sh2_conn_close(ctx, user_conn);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (recv error after handshake)");
        continue;
      }
    }

    conn->last_active_poll = ctx->poll_count;

    SH2_CHECK(shift_entity_move_one(sh, entities[i], sio_colls->read_in),
              "recycle read buffer (handshake done)");
  }
}
#endif /* SH2_HAS_TLS */

/* --------------------------------------------------------------------------
 * Pass 4: Feed active data to nghttp2
 * -------------------------------------------------------------------------- */

void sh2_reads_feed_data(sh2_context_t *ctx) {
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

    sh2_conn_t *conn = sh2_conn_get(ctx, user_conn);
    if (!conn || !conn->ng_session) {
      SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                "destroy read entity (no session)");
      continue;
    }

#ifdef SH2_HAS_TLS
    if (conn->tls) {
      /* TLS: decrypt raw TCP → plaintext → nghttp2 */
      uint8_t decrypt_buf[65536];
      uint32_t decrypt_len = 0;

      sh2_tls_feed_result_t r = sh2_tls_feed(conn,
                                             rbufs[i].data, rbufs[i].len,
                                             decrypt_buf, sizeof(decrypt_buf),
                                             &decrypt_len);
      if (r == SH2_TLS_ERROR) {
        sh2_conn_close(ctx, user_conn);
        SH2_CHECK(shift_entity_destroy_one(sh, entities[i]),
                  "destroy read entity (tls decrypt error)");
        continue;
      }

      if (decrypt_len > 0) {
        nghttp2_ssize consumed =
            nghttp2_session_mem_recv(conn->ng_session, decrypt_buf, decrypt_len);
        if (consumed < 0) {
          sh2_conn_close(ctx, user_conn);
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
        sh2_conn_close(ctx, user_conn);
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
