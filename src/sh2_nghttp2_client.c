#include "sh2_nghttp2_client.h"
#include "sh2_nghttp2.h"

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
 * Populate response components on the existing request entity.
 * The entity stays in coll_client_request_sending — the single move to
 * stream_result_out happens in stream_finish_client when the stream closes.
 * -------------------------------------------------------------------------- */

static void stream_emit_response(sh2_context_t *ctx, sh2_stream_t *stream) {
    shift_t *sh = ctx->shift;
    shift_entity_t entity = stream->entity;

    /* resp_headers — finalize and transfer ownership */
    uint32_t hdr_count = 0;
    sh2_header_field_t *fields = sh2_stream_hdr_finalize(stream, &hdr_count);

    sh2_resp_headers_t *rh = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.resp_headers,
                                          (void **)&rh),
              "get resp_headers (client response)");
    rh->fields = fields;
    rh->count  = hdr_count;

    /* resp_body — transfer ownership */
    sh2_resp_body_t *rb = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.resp_body,
                                          (void **)&rb),
              "get resp_body (client response)");
    rb->data = stream->body_data;
    rb->len  = stream->body_len;
    stream->body_data = NULL;
    stream->body_len  = 0;
    stream->body_cap  = 0;

    /* status */
    sh2_status_t *st = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.status,
                                          (void **)&st),
              "get status (client response)");
    st->code = stream->response_status;
}

/* --------------------------------------------------------------------------
 * Client nghttp2 callbacks
 * -------------------------------------------------------------------------- */

static int on_begin_headers_client(nghttp2_session *session,
                                   const nghttp2_frame *frame,
                                   void *user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
        return 0;

    /* stream was already allocated at request submission time */
    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (stream)
        return 0;

    /* fallback: allocate for streams we didn't initiate (e.g. server push) */
    sh2_ng_ctx_t *nctx = user_data;
    stream = sh2_stream_alloc(nctx->conn_idx);
    if (!stream)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream);
    return 0;
}

static int on_header_client(nghttp2_session *session,
                            const nghttp2_frame *frame,
                            const uint8_t *name, size_t namelen,
                            const uint8_t *value, size_t valuelen,
                            uint8_t flags, void *user_data) {
    (void)flags; (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;

    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!stream) return 0;

    /* parse :status pseudo-header */
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        stream->response_status = (uint16_t)atoi((const char *)value);
    }

    if (!sh2_stream_hdr_append(stream, name, namelen, value, valuelen))
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static int on_data_chunk_recv_client(nghttp2_session *session, uint8_t flags,
                                     int32_t stream_id, const uint8_t *data,
                                     size_t len, void *user_data) {
    (void)flags; (void)user_data;
    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    if (!sh2_stream_body_append(stream, data, len))
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static int on_frame_recv_client(nghttp2_session *session,
                                const nghttp2_frame *frame,
                                void *user_data) {
    sh2_ng_ctx_t *nctx = user_data;

    if (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA)
        return 0;

    if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        return 0;

    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!stream) return 0;

    stream_emit_response(nctx->ctx, stream);
    return 0;
}

static void stream_finish_client(sh2_context_t *ctx, sh2_stream_t *stream,
                                 uint32_t error_code) {
    shift_t *sh = ctx->shift;

    sh2_io_result_t *io = NULL;
    SH2_CHECK(shift_entity_get_component(sh, stream->entity, ctx->comp_ids.io_result,
                                          (void **)&io),
              "get io_result (client stream_finish)");
    io->error = error_code ? -1 : 0;

    SH2_CHECK(shift_entity_move_one(sh, stream->entity,
                          ctx->coll_ids_client.stream_result_out),
              "move entity to client result_out");
}

static int on_stream_close_client(nghttp2_session *session, int32_t stream_id,
                                  uint32_t error_code, void *user_data) {
    sh2_ng_ctx_t *nctx = user_data;
    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    stream_finish_client(nctx->ctx, stream, error_code);

    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    sh2_stream_free(stream);
    return 0;
}

/* --------------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_nghttp2_client_init_callbacks(sh2_context_t *ctx) {
    nghttp2_session_callbacks *cb;
    if (nghttp2_session_callbacks_new(&cb) != 0)
        return sh2_error_oom;

    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, on_begin_headers_client);
    nghttp2_session_callbacks_set_on_header_callback(cb, on_header_client);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_data_chunk_recv_client);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv_client);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_stream_close_client);

    ctx->ng_client_callbacks = cb;
    return sh2_ok;
}

sh2_result_t sh2_nghttp2_client_session_create(sh2_context_t *ctx,
                                                uint32_t conn_idx) {
    sh2_conn_t *conn = &ctx->conns[conn_idx];

    sh2_ng_ctx_t *nctx = malloc(sizeof(*nctx));
    if (!nctx) return sh2_error_oom;
    nctx->ctx      = ctx;
    nctx->conn_idx = conn_idx;

    int rv = nghttp2_session_client_new(&conn->ng_session,
                                        ctx->ng_client_callbacks, nctx);
    if (rv != 0) {
        free(nctx);
        return sh2_error_oom;
    }
    conn->ng_ctx = nctx;

    /* submit initial SETTINGS */
    nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 128 },
    };
    nghttp2_submit_settings(conn->ng_session, NGHTTP2_FLAG_NONE,
                            settings,
                            sizeof(settings) / sizeof(settings[0]));

    return sh2_ok;
}
