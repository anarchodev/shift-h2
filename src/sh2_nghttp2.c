#include "sh2_nghttp2.h"

#include <assert.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Stream helpers
 * -------------------------------------------------------------------------- */

sh2_stream_t *sh2_stream_alloc(shift_entity_t conn_entity) {
    sh2_stream_t *s = calloc(1, sizeof(*s));
    if (s) s->conn_entity = conn_entity;
    return s;
}

void sh2_stream_free(sh2_stream_t *s) {
    if (!s) return;
    free(s->hdr_fields);
    free(s->hdr_strbuf);
    free(s->body_data);
    free(s->send_data);
    free(s);
}

bool sh2_stream_hdr_append(sh2_stream_t *s,
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
sh2_header_field_t *sh2_stream_hdr_finalize(sh2_stream_t *s,
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

sh2_body_data_t *sh2_body_data_alloc(const void *data, uint32_t len) {
    sh2_body_data_t *rd = malloc(sizeof(*rd) + len);
    if (!rd) return NULL;
    void *copy = (uint8_t *)rd + sizeof(*rd);
    memcpy(copy, data, len);
    rd->data   = copy;
    rd->len    = len;
    rd->offset = 0;
    return rd;
}

bool sh2_stream_body_append(sh2_stream_t *s,
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
    sh2_conn_t *conn = sh2_conn_get(ctx, stream->conn_entity);

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
    sess->entity = stream->conn_entity;

    /* req_headers — finalize and transfer ownership */
    uint32_t hdr_count = 0;
    sh2_header_field_t *fields = sh2_stream_hdr_finalize(stream, &hdr_count);

    sh2_req_headers_t *rh = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.req_headers,
                                          (void **)&rh),
              "get req_headers component");
    rh->fields = fields;
    rh->count  = fields ? hdr_count : 0;

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

    /* domain_tag — propagate from per-connection TLS state */
    sh2_domain_tag_t *dt = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.domain_tag,
                                          (void **)&dt),
              "get domain_tag component");
#ifdef SH2_HAS_TLS
    dt->tag = (conn && conn->tls) ? conn->tls->domain_tag : 0;
#else
    (void)conn;
    dt->tag = 0;
#endif

    /* peer_cert — copy from per-connection TLS state (strings are strdup'd
     * so the entity's copy is independent of the connection lifetime) */
    sh2_peer_cert_t *pc = NULL;
    SH2_CHECK(shift_entity_get_component(sh, entity, ctx->comp_ids.peer_cert,
                                          (void **)&pc),
              "get peer_cert component");
#ifdef SH2_HAS_TLS
    if (conn && conn->tls && conn->tls->peer_cert.present) {
        const sh2_peer_cert_t *src = &conn->tls->peer_cert;
        pc->present    = true;
        pc->subject_cn = src->subject_cn ? strdup(src->subject_cn) : NULL;
        pc->subject_dn = src->subject_dn ? strdup(src->subject_dn) : NULL;
        pc->issuer_dn  = src->issuer_dn  ? strdup(src->issuer_dn)  : NULL;
        pc->serial_hex = src->serial_hex ? strdup(src->serial_hex) : NULL;
        memcpy(pc->fingerprint_sha256, src->fingerprint_sha256, 32);
    }
#endif

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
    sh2_stream_t *stream = sh2_stream_alloc(nctx->conn_entity);
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

    if (!sh2_stream_hdr_append(stream, name, namelen, value, valuelen))
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
}

int sh2_on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
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

void sh2_stream_finish(sh2_context_t *ctx, sh2_stream_t *stream,
                       uint32_t error_code, shift_collection_id_t dest) {
    shift_t *sh = ctx->shift;

    sh2_io_result_t *io = NULL;
    SH2_CHECK(shift_entity_get_component(sh, stream->entity, ctx->comp_ids.io_result,
                                          (void **)&io),
              "get io_result (stream_finish)");
    io->error = error_code ? -1 : 0;

    SH2_CHECK(shift_entity_move_one(sh, stream->entity, dest),
              "move entity to result_out (stream_finish)");
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *user_data) {
    sh2_ng_ctx_t *nctx = user_data;
    sh2_stream_t *stream = nghttp2_session_get_stream_user_data(
        session, stream_id);
    if (!stream) return 0;

    if (stream->emitted) {
        /* if send isn't complete, treat as error regardless of error_code */
        uint32_t ec = stream->send_complete
            ? error_code
            : (error_code ? error_code : SH2_ERR_SEND_INCOMPLETE);
        sh2_stream_finish(nctx->ctx, stream, ec,
                          nctx->ctx->coll_ids.response_out);
    }

    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    sh2_stream_free(stream);
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

    sh2_body_data_t *rd = source->ptr;
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
        if (stream) {
            stream->send_complete = true;
            stream->send_data    = NULL;
        }

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
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, sh2_on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_stream_close);

    ctx->ng_callbacks = cb;
    return sh2_ok;
}

sh2_result_t sh2_nghttp2_session_create(sh2_context_t *ctx,
                                         shift_entity_t conn_entity) {
    sh2_conn_t *conn = sh2_conn_get(ctx, conn_entity);
    if (!conn) return sh2_error_invalid;

    sh2_ng_ctx_t *nctx = malloc(sizeof(*nctx));
    if (!nctx) return sh2_error_oom;
    nctx->ctx              = ctx;
    nctx->conn_entity = conn_entity;

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
    if (nghttp2_submit_settings(conn->ng_session, NGHTTP2_FLAG_NONE,
                                settings,
                                sizeof(settings) / sizeof(settings[0])) != 0) {
        nghttp2_session_del(conn->ng_session);
        conn->ng_session = NULL;
        free(nctx);
        conn->ng_ctx = NULL;
        return sh2_error_invalid;
    }

    return sh2_ok;
}

void sh2_nghttp2_session_destroy(sh2_context_t *ctx,
                                  shift_entity_t conn_entity) {
    sh2_conn_t *conn = sh2_conn_get(ctx, conn_entity);
    if (!conn || !conn->ng_session) return;

    /* Terminate session — this causes nghttp2 to mark all open streams
     * as closed, firing on_stream_close callbacks during the next
     * mem_send so entities move to response_out. */
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

    nghttp2_session_del(conn->ng_session);
    conn->ng_session = NULL;

    free(conn->ng_ctx);
    conn->ng_ctx = NULL;
}

/* Helper: submit a sio write entity with the given data buffer (takes ownership) */
static sh2_result_t submit_write(sh2_context_t *ctx,
                                  shift_entity_t conn_entity,
                                  void *data, uint32_t len) {
    sh2_conn_t *conn = sh2_conn_get(ctx, conn_entity);
    if (!conn) return sh2_error_invalid;
    shift_t *sh = ctx->shift;
    const sio_collection_ids_t *sio_colls = sio_get_collection_ids(ctx->sio);

    shift_entity_t we;
    SH2_CHECK(shift_entity_create_one_begin(sh, sio_colls->write_in, &we),
              "create write entity");

    sio_write_buf_t *wb = NULL;
    SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.write_buf,
                                          (void **)&wb),
              "get write_buf component");
    wb->data   = data;
    wb->len    = len;
    wb->offset = 0;

    sio_conn_entity_t *ce = NULL;
    SH2_CHECK(shift_entity_get_component(sh, we, ctx->sio_comp_ids.conn_entity,
                                          (void **)&ce),
              "get conn_entity component (write)");
    ce->entity = conn_entity;

    SH2_CHECK(shift_entity_create_one_end(sh, we), "create_end write entity");
    conn->pending_writes++;
    return sh2_ok;
}

sh2_result_t sh2_drive_send(sh2_context_t *ctx,
                             shift_entity_t conn_entity) {
    sh2_conn_t *conn = sh2_conn_get(ctx, conn_entity);
    if (!conn || !conn->ng_session)
        return sh2_ok;

    shift_t *sh = ctx->shift;

#ifdef SH2_HAS_TLS
    if (conn->tls) {
        /* TLS mode: accumulate all nghttp2 output, then encrypt as one chunk */
        uint8_t *accum = NULL;
        size_t accum_len = 0;
        size_t accum_cap = 0;

        for (;;) {
            const uint8_t *data;
            nghttp2_ssize len = nghttp2_session_mem_send(conn->ng_session, &data);
            if (len < 0) { free(accum); return sh2_error_io; }
            if (len == 0) break;

            /* grow accumulation buffer */
            if (accum_len + (size_t)len > accum_cap) {
                size_t new_cap = accum_cap ? accum_cap * 2 : 16384;
                while (new_cap < accum_len + (size_t)len) new_cap *= 2;
                uint8_t *nb = realloc(accum, new_cap);
                if (!nb) { free(accum); return sh2_error_oom; }
                accum = nb;
                accum_cap = new_cap;
            }
            memcpy(accum + accum_len, data, (size_t)len);
            accum_len += (size_t)len;
        }

        if (accum_len > 0) {
            uint8_t *cipher = NULL;
            uint32_t cipher_len = 0;
            sh2_result_t r = sh2_tls_encrypt(conn, accum, (uint32_t)accum_len,
                                              &cipher, &cipher_len);
            free(accum);
            if (r != sh2_ok) return r;

            if (cipher && cipher_len > 0) {
                r = submit_write(ctx, conn_entity, cipher, cipher_len);
                if (r != sh2_ok) { free(cipher); return r; }
            }
        } else {
            free(accum);
        }
    } else
#endif
    {
        /* h2c mode: send plaintext directly */
        for (;;) {
            const uint8_t *data;
            nghttp2_ssize len = nghttp2_session_mem_send(conn->ng_session, &data);
            if (len < 0)
                return sh2_error_io;
            if (len == 0)
                break;

            void *copy = malloc((size_t)len);
            if (!copy) return sh2_error_oom;
            memcpy(copy, data, (size_t)len);

            sh2_result_t r = submit_write(ctx, conn_entity, copy, (uint32_t)len);
            if (r != sh2_ok) { free(copy); return r; }
        }
    }

    /* Re-fetch conn after potential flush in submit_write */
    conn = sh2_conn_get(ctx, conn_entity);
    if (!conn) return sh2_ok;

    /* check if session is done — defer fd close until writes complete */
    if (!nghttp2_session_want_read(conn->ng_session) &&
        !nghttp2_session_want_write(conn->ng_session)) {
        sh2_nghttp2_session_destroy(ctx, conn_entity);

        /* Re-fetch after session_destroy flush */
        conn = sh2_conn_get(ctx, conn_entity);
        if (!conn) return sh2_ok;

        if (conn->pending_writes > 0) {
            /* move to draining — writes_finalize_draining will clean up */
            SH2_CHECK(shift_entity_move_one(sh, conn_entity,
                          ctx->coll_conn_draining),
                      "move to draining (drive_send)");
        } else {
            /* no pending writes — destroy connection entities immediately */
            if (!shift_entity_is_stale(sh, conn_entity))
                SH2_CHECK(shift_entity_destroy_one(sh, conn_entity),
                          "destroy conn_entity (drive_send)");
        }
    }

    return sh2_ok;
}

void sh2_conn_close(sh2_context_t *ctx, shift_entity_t conn_entity) {
    sh2_conn_t *conn = sh2_conn_get(ctx, conn_entity);
    if (!conn) return;
    if (!conn->ng_session
#ifdef SH2_HAS_TLS
        && !conn->tls
#endif
       ) return;

    shift_t *sh = ctx->shift;

#ifdef SH2_HAS_TLS
    sh2_tls_conn_destroy(conn);
#endif

    sh2_nghttp2_session_destroy(ctx, conn_entity);

    /* Re-fetch after session_destroy flush */
    conn = sh2_conn_get(ctx, conn_entity);

    /* destroy sio entities — triggers fd close via conn_dtor */
    if (conn && !shift_entity_is_stale(sh, conn_entity))
        SH2_CHECK(shift_entity_destroy_one(sh, conn_entity),
                  "destroy conn_entity (conn_close)");
}
