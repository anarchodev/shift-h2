#include "sh2_nghttp2.h"

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
 * Stream helpers
 * -------------------------------------------------------------------------- */

static sh2_stream_t *stream_alloc(uint32_t conn_idx) {
    sh2_stream_t *s = calloc(1, sizeof(*s));
    if (s) s->conn_idx = conn_idx;
    return s;
}

static void stream_free(sh2_stream_t *s) {
    if (!s) return;
    free(s->hdr_fields);
    free(s->hdr_strbuf);
    free(s->body_data);
    free(s);
}

static bool stream_hdr_append(sh2_stream_t *s,
                              const uint8_t *name,  size_t namelen,
                              const uint8_t *value, size_t valuelen) {
    /* grow fields array */
    if (s->hdr_count == s->hdr_cap) {
        uint32_t new_cap = s->hdr_cap ? s->hdr_cap * 2 : 16;
        sh2_header_field_t *f = realloc(s->hdr_fields,
                                        new_cap * sizeof(*f));
        if (!f) return false;
        s->hdr_fields = f;
        s->hdr_cap    = new_cap;
    }

    /* grow string buffer */
    uint32_t need = namelen + valuelen;
    while (s->hdr_strbuf_len + need > s->hdr_strbuf_cap) {
        uint32_t new_cap = s->hdr_strbuf_cap ? s->hdr_strbuf_cap * 2 : 1024;
        char *b = realloc(s->hdr_strbuf, new_cap);
        if (!b) return false;
        s->hdr_strbuf     = b;
        s->hdr_strbuf_cap = new_cap;
    }

    /* copy name and value into strbuf, store offsets temporarily */
    uint32_t name_off = s->hdr_strbuf_len;
    memcpy(s->hdr_strbuf + name_off, name, namelen);
    s->hdr_strbuf_len += namelen;

    uint32_t value_off = s->hdr_strbuf_len;
    memcpy(s->hdr_strbuf + value_off, value, valuelen);
    s->hdr_strbuf_len += valuelen;

    /* store as offsets (rebased to pointers in finalize) */
    s->hdr_fields[s->hdr_count++] = (sh2_header_field_t){
        .name      = (const char *)(uintptr_t)name_off,
        .name_len  = (uint32_t)namelen,
        .value     = (const char *)(uintptr_t)value_off,
        .value_len = (uint32_t)valuelen,
    };

    return true;
}

/* Bake offset-based header fields into a single contiguous allocation.
 * Returns the fields array (with embedded string data after the fields).
 * Caller takes ownership. */
static sh2_header_field_t *stream_hdr_finalize(sh2_stream_t *s,
                                                uint32_t *out_count) {
    uint32_t n = s->hdr_count;
    size_t fields_size = n * sizeof(sh2_header_field_t);
    size_t total = fields_size + s->hdr_strbuf_len;

    sh2_header_field_t *result = malloc(total);
    if (!result) return NULL;

    char *strbuf = (char *)result + fields_size;
    memcpy(strbuf, s->hdr_strbuf, s->hdr_strbuf_len);

    for (uint32_t i = 0; i < n; i++) {
        uintptr_t name_off  = (uintptr_t)s->hdr_fields[i].name;
        uintptr_t value_off = (uintptr_t)s->hdr_fields[i].value;
        result[i] = (sh2_header_field_t){
            .name      = strbuf + name_off,
            .name_len  = s->hdr_fields[i].name_len,
            .value     = strbuf + value_off,
            .value_len = s->hdr_fields[i].value_len,
        };
    }

    *out_count = n;
    return result;
}

static bool stream_body_append(sh2_stream_t *s,
                               const uint8_t *data, size_t len) {
    while (s->body_len + len > s->body_cap) {
        uint32_t new_cap = s->body_cap ? s->body_cap * 2 : 4096;
        uint8_t *b = realloc(s->body_data, new_cap);
        if (!b) return false;
        s->body_data = b;
        s->body_cap  = new_cap;
    }
    memcpy(s->body_data + s->body_len, data, len);
    s->body_len += len;
    return true;
}

/* --------------------------------------------------------------------------
 * Emit a completed request into request_out
 * -------------------------------------------------------------------------- */

static void stream_emit_request(sh2_context_t *ctx, sh2_stream_t *stream,
                                int32_t stream_id) {
    shift_t *sh = ctx->shift;

    shift_entity_t entity;
    SH2_CHECK(shift_entity_create_one_begin(sh, ctx->coll_ids.request_out,
                                             &entity),
              "create request entity");

    /* stream_id */
    sh2_stream_id_t *sid = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.stream_id,
                                          (void **)&sid),
              "get stream_id component");
    sid->id = (uint32_t)stream_id;

    /* session — use the user_conn entity for staleness tracking */
    sh2_session_t *sess = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.session,
                                          (void **)&sess),
              "get session component");
    sess->entity = ctx->conns[stream->conn_idx].user_conn_entity;

    /* req_headers — finalize and transfer ownership */
    uint32_t hdr_count = 0;
    sh2_header_field_t *fields = stream_hdr_finalize(stream, &hdr_count);

    sh2_req_headers_t *rh = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.req_headers,
                                          (void **)&rh),
              "get req_headers component");
    rh->fields = fields;
    rh->count  = hdr_count;

    /* req_body — transfer ownership */
    sh2_req_body_t *rb = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.req_body,
                                          (void **)&rb),
              "get req_body component");
    rb->data = stream->body_data;
    rb->len  = stream->body_len;
    stream->body_data = NULL;
    stream->body_len  = 0;
    stream->body_cap  = 0;

    SH2_CHECK(shift_entity_create_end(sh, &entity, 1), "create_end request entity");

    stream->entity  = entity;
    stream->emitted = true;
}

/* --------------------------------------------------------------------------
 * nghttp2 callbacks
 * -------------------------------------------------------------------------- */

static int on_begin_headers(nghttp2_session *session,
                            const nghttp2_frame *frame, void *user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;

    sh2_ng_ctx_t *nctx = user_data;
    sh2_stream_t *stream = stream_alloc(nctx->conn_idx);
    if (!stream)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream);
    return 0;
}

static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags, void *user_data) {
    (void)flags; (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;

    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!stream) return 0;

    if (!stream_hdr_append(stream, name, namelen, value, valuelen))
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id, const uint8_t *data,
                              size_t len, void *user_data) {
    (void)flags; (void)user_data;
    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    if (!stream_body_append(stream, data, len))
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

static int on_frame_recv(nghttp2_session *session,
                         const nghttp2_frame *frame, void *user_data) {
    sh2_ng_ctx_t *nctx = user_data;

    if (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA)
        return 0;

    if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        return 0;

    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!stream || stream->emitted) return 0;

    stream_emit_request(nctx->ctx, stream, frame->hd.stream_id);
    return 0;
}

static void stream_finish(sh2_context_t *ctx, sh2_stream_t *stream,
                          uint32_t error_code) {
    shift_t *sh = ctx->shift;

    sh2_io_result_t *io = NULL;
    SH2_CHECK(shift_entity_get_component(sh, stream->entity, ctx->comp_ids.io_result,
                                          (void **)&io),
              "get io_result (stream_finish)");
    io->error = error_code ? -1 : 0;

    SH2_CHECK(shift_entity_move_one(sh, stream->entity,
                          ctx->coll_ids.response_result_out),
              "move entity to result_out (stream_finish)");
}

static _Thread_local uint64_t g_stream_close_count = 0;
static _Thread_local uint64_t g_stream_close_emitted = 0;
static _Thread_local uint64_t g_stream_close_not_emitted = 0;

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *user_data) {
    sh2_ng_ctx_t *nctx = user_data;
    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    g_stream_close_count++;

    if (stream->emitted) {
        g_stream_close_emitted++;
        /* if send isn't complete, treat as error regardless of error_code */
        uint32_t ec = stream->send_complete ? error_code : (error_code ? error_code : 1);
        stream_finish(nctx->ctx, stream, ec);
    } else {
        g_stream_close_not_emitted++;
    }

    if (g_stream_close_count % 10000 == 0) {
        fprintf(stderr, "[stream_close] total=%lu emitted=%lu not_emitted=%lu\n",
                (unsigned long)g_stream_close_count,
                (unsigned long)g_stream_close_emitted,
                (unsigned long)g_stream_close_not_emitted);
    }

    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    stream_free(stream);
    return 0;
}

/* --------------------------------------------------------------------------
 * Response data provider
 * -------------------------------------------------------------------------- */

nghttp2_ssize on_data_source_read(
    nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data) {
    (void)user_data;

    sh2_resp_data_t *rd = source->ptr;
    size_t remaining = rd->len - rd->offset;
    size_t to_copy = remaining < length ? remaining : length;

    memcpy(buf, (const uint8_t *)rd->data + rd->offset, to_copy);
    rd->offset += to_copy;

    if (rd->offset >= rd->len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

        /* mark stream as send-complete so on_stream_close knows
         * it's safe to hand the entity back to the user */
        sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
            session, stream_id);
        if (stream)
            stream->send_complete = true;

        free(rd);
    }

    return (nghttp2_ssize)to_copy;
}

/* --------------------------------------------------------------------------
 * Public functions
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_nghttp2_init_callbacks(sh2_context_t *ctx) {
    nghttp2_session_callbacks *cb;
    if (nghttp2_session_callbacks_new(&cb) != 0)
        return sh2_error_oom;

    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cb, on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_stream_close);

    ctx->ng_callbacks = cb;
    return sh2_ok;
}

sh2_result_t sh2_nghttp2_session_create(sh2_context_t *ctx, uint32_t conn_idx) {
    sh2_conn_t *conn = &ctx->conns[conn_idx];

    sh2_ng_ctx_t *nctx = malloc(sizeof(*nctx));
    if (!nctx) return sh2_error_oom;
    nctx->ctx      = ctx;
    nctx->conn_idx = conn_idx;

    int rv = nghttp2_session_server_new(&conn->ng_session,
                                        ctx->ng_callbacks, nctx);
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

void sh2_nghttp2_session_destroy(sh2_context_t *ctx, uint32_t conn_idx) {
    sh2_conn_t *conn = &ctx->conns[conn_idx];
    if (!conn->ng_session) return;

    /* Terminate session — this causes nghttp2 to mark all open streams
     * as closed, firing on_stream_close callbacks during the next
     * mem_send so entities move to response_result_out. */
    {
        size_t before = 0;
        shift_entity_t *tmp = NULL;
        shift_collection_get_entities(ctx->shift, ctx->coll_response_sending,
                                      &tmp, &before);
        nghttp2_session_terminate_session(conn->ng_session, NGHTTP2_NO_ERROR);

        /* Drive the session to flush stream close callbacks */
        for (;;) {
            const uint8_t *data;
            nghttp2_ssize len = nghttp2_session_mem_send(conn->ng_session, &data);
            if (len <= 0) break;
            /* discard output — connection is going away */
        }

        /* flush deferred moves from on_stream_close callbacks */
        SH2_CHECK(shift_flush(ctx->shift), "shift_flush (session_destroy)");

        size_t after = 0;
        shift_collection_get_entities(ctx->shift, ctx->coll_response_sending,
                                      &tmp, &after);
        fprintf(stderr, "[session_destroy] conn=%u sending: %zu -> %zu (drained %zu)\n",
                conn_idx, before, after, before - after);
    }

    nghttp2_session_del(conn->ng_session);
    conn->ng_session = NULL;

    free(conn->ng_ctx);
    conn->ng_ctx = NULL;
}

sh2_result_t sh2_drive_send(sh2_context_t *ctx, uint32_t conn_idx) {
    sh2_conn_t *conn = &ctx->conns[conn_idx];
    if (!conn->ng_session)
        return sh2_ok;

    shift_t *sh = ctx->shift;
    const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

    for (;;) {
        const uint8_t *data;
        nghttp2_ssize len = nghttp2_session_mem_send(conn->ng_session, &data);
        if (len < 0)
            return sh2_error_io;
        if (len == 0)
            break;

        /* copy data — nghttp2 buffer is only valid until next session call */
        void *copy = malloc((size_t)len);
        if (!copy) return sh2_error_oom;
        memcpy(copy, data, (size_t)len);

        shift_entity_t we;
        SH2_CHECK(shift_entity_create_one_begin(sh, sio_colls->write_in, &we),
                  "create write entity");

        sio_write_buf_t *wb = NULL;
        SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.write_buf,
                                              (void **)&wb),
                  "get write_buf component");
        wb->data   = copy;
        wb->len    = (uint32_t)len;
        wb->offset = 0;

        sio_conn_entity_t *ce = NULL;
        SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.conn_entity,
                                              (void **)&ce),
                  "get conn_entity component (write)");
        ce->entity = conn->conn_entity;

        sio_user_conn_entity_t *uce = NULL;
        SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.user_conn_entity,
                                              (void **)&uce),
                  "get user_conn_entity component (write)");
        uce->entity = conn->user_conn_entity;

        SH2_CHECK(shift_entity_create_one_end(sh, we), "create_end write entity");
        conn->pending_writes++;
    }

    /* check if session is done — defer fd close until writes complete */
    if (!nghttp2_session_want_read(conn->ng_session) &&
        !nghttp2_session_want_write(conn->ng_session)) {
        /* mark closed so no more reads are processed */
        if (!shift_entity_is_stale(sh, conn->user_conn_entity)) {
            sh2_conn_idx_t *cidx = NULL;
            SH2_CHECK(shift_entity_get_component(sh, conn->user_conn_entity,
                                                  ctx->internal_conn_idx, (void **)&cidx),
                      "get conn_idx (drive_send close)");
            cidx->state = SH2_CONN_CLOSED;
        }
        sh2_nghttp2_session_destroy(ctx, conn_idx);

        if (conn->pending_writes > 0) {
            conn->draining = true;
        } else {
            /* no pending writes — close fd immediately */
            if (!shift_entity_is_stale(sh, conn->conn_entity))
                SH2_CHECK(shift_entity_destroy_one(sh, conn->conn_entity),
                          "destroy conn_entity (drive_send)");
            if (!shift_entity_is_stale(sh, conn->user_conn_entity))
                SH2_CHECK(shift_entity_destroy_one(sh, conn->user_conn_entity),
                          "destroy user_conn_entity (drive_send)");
            *conn = (sh2_conn_t){0};
        }
    }

    return sh2_ok;
}

void sh2_conn_close(sh2_context_t *ctx, uint32_t conn_idx) {
    sh2_conn_t *conn = &ctx->conns[conn_idx];
    if (!conn->ng_session && !conn->draining) return;

    shift_t *sh = ctx->shift;

    /* mark conn_idx as closed so stale reads are discarded */
    if (!shift_entity_is_stale(sh, conn->user_conn_entity)) {
        sh2_conn_idx_t *cidx = NULL;
        SH2_CHECK(shift_entity_get_component(sh, conn->user_conn_entity,
                                              ctx->internal_conn_idx, (void **)&cidx),
                  "get conn_idx (conn_close)");
        cidx->state = SH2_CONN_CLOSED;
    }

    sh2_nghttp2_session_destroy(ctx, conn_idx);

    /* destroy sio entities — triggers fd close */
    if (!shift_entity_is_stale(sh, conn->conn_entity))
        SH2_CHECK(shift_entity_destroy_one(sh, conn->conn_entity),
                  "destroy conn_entity (conn_close)");
    if (!shift_entity_is_stale(sh, conn->user_conn_entity))
        SH2_CHECK(shift_entity_destroy_one(sh, conn->user_conn_entity),
                  "destroy user_conn_entity (conn_close)");

    *conn = (sh2_conn_t){0};
}

