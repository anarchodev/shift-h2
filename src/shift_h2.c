#include "shift_h2_internal.h"
#include "sh2_nghttp2.h"

#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Component destructors
 * -------------------------------------------------------------------------- */

static void req_headers_dtor(shift_t *ctx, shift_collection_id_t col_id,
                             const shift_entity_t *entities, void *data,
                             uint32_t offset, uint32_t count, void *user_data) {
    (void)ctx; (void)col_id; (void)entities; (void)user_data;
    sh2_req_headers_t *hdrs = (sh2_req_headers_t *)data + offset;
    for (uint32_t i = 0; i < count; i++) {
        free(hdrs[i].fields);
        hdrs[i].fields = NULL;
        hdrs[i].count  = 0;
    }
}

static void req_body_dtor(shift_t *ctx, shift_collection_id_t col_id,
                          const shift_entity_t *entities, void *data,
                          uint32_t offset, uint32_t count, void *user_data) {
    (void)ctx; (void)col_id; (void)entities; (void)user_data;
    sh2_req_body_t *bodies = (sh2_req_body_t *)data + offset;
    for (uint32_t i = 0; i < count; i++) {
        free(bodies[i].data);
        bodies[i].data = NULL;
        bodies[i].len  = 0;
    }
}

static void resp_headers_dtor(shift_t *ctx, shift_collection_id_t col_id,
                              const shift_entity_t *entities, void *data,
                              uint32_t offset, uint32_t count, void *user_data) {
    (void)ctx; (void)col_id; (void)entities; (void)user_data;
    sh2_resp_headers_t *hdrs = (sh2_resp_headers_t *)data + offset;
    for (uint32_t i = 0; i < count; i++) {
        free(hdrs[i].fields);
        hdrs[i].fields = NULL;
        hdrs[i].count  = 0;
    }
}

static void resp_body_dtor(shift_t *ctx, shift_collection_id_t col_id,
                           const shift_entity_t *entities, void *data,
                           uint32_t offset, uint32_t count, void *user_data) {
    (void)ctx; (void)col_id; (void)entities; (void)user_data;
    sh2_resp_body_t *bodies = (sh2_resp_body_t *)data + offset;
    for (uint32_t i = 0; i < count; i++) {
        free((void *)bodies[i].data);
        bodies[i].data = NULL;
        bodies[i].len  = 0;
    }
}

/* --------------------------------------------------------------------------
 * sh2_register_components
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_register_components(shift_t *sh, sh2_component_ids_t *out) {
    if (!sh || !out) return sh2_error_null;

    shift_result_t r;

#define REG(field, type)                                                      \
    r = shift_component_register(sh,                                          \
        &(shift_component_info_t){ .element_size = sizeof(type) },            \
        &out->field);                                                         \
    if (r != shift_ok) return sh2_error_invalid;

#define REG_EX(field, type, dtor_fn)                                          \
    r = shift_component_register(sh,                                          \
        &(shift_component_info_t){                                            \
            .element_size = sizeof(type),                                     \
            .destructor   = (dtor_fn),                                        \
        },                                                                    \
        &out->field);                                                         \
    if (r != shift_ok) return sh2_error_invalid;

    REG(stream_id,    sh2_stream_id_t)
    REG(session,      sh2_session_t)
    REG_EX(req_headers, sh2_req_headers_t, req_headers_dtor)
    REG_EX(req_body,    sh2_req_body_t,    req_body_dtor)
    REG_EX(resp_headers, sh2_resp_headers_t, resp_headers_dtor)
    REG_EX(resp_body,    sh2_resp_body_t,    resp_body_dtor)
    REG(status,       sh2_status_t)
    REG(io_result,    sh2_io_result_t)
    REG(domain_tag,   sh2_domain_tag_t)

#undef REG
#undef REG_EX

    return sh2_ok;
}

/* --------------------------------------------------------------------------
 * sh2_context_create / destroy
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_context_create(const sh2_config_t *cfg, sh2_context_t **out) {
    if (!cfg || !out || !cfg->shift) return sh2_error_null;

    sh2_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return sh2_error_oom;

    ctx->shift    = cfg->shift;
    ctx->comp_ids = cfg->comp_ids;

    ctx->coll_ids.request_out         = cfg->request_out;
    ctx->coll_ids.response_in         = cfg->response_in;
    ctx->coll_ids.response_result_out = cfg->response_result_out;

    /* register sio components */
    if (sio_register_components(ctx->shift, &ctx->sio_comp_ids) != sio_ok) {
        free(ctx);
        return sh2_error_invalid;
    }

    /* register internal conn_idx component */
    {
        shift_component_info_t ci = { .element_size = sizeof(sh2_conn_idx_t) };
        if (shift_component_register(ctx->shift, &ci,
                                      &ctx->internal_conn_idx) != shift_ok) {
            free(ctx);
            return sh2_error_invalid;
        }
    }

    /* create sio result collections */
    {
        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.conn_entity,
            ctx->internal_conn_idx,
        };
        shift_collection_info_t ci = {
            .name       = "sio_connection_results",
            .comp_ids   = comps,
            .comp_count = sizeof(comps) / sizeof(comps[0]),
        };
        if (shift_collection_register(ctx->shift, &ci,
                                      &ctx->sio_connection_results) != shift_ok) {
            free(ctx);
            return sh2_error_invalid;
        }
    }
    {
        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.read_buf,
            ctx->sio_comp_ids.io_result,
            ctx->sio_comp_ids.conn_entity,
            ctx->sio_comp_ids.user_conn_entity,
        };
        shift_collection_info_t ci = {
            .name       = "sio_read_results",
            .comp_ids   = comps,
            .comp_count = sizeof(comps) / sizeof(comps[0]),
        };
        if (shift_collection_register(ctx->shift, &ci,
                                      &ctx->sio_read_results) != shift_ok) {
            free(ctx);
            return sh2_error_invalid;
        }
    }
    {
        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.write_buf,
            ctx->sio_comp_ids.io_result,
            ctx->sio_comp_ids.conn_entity,
            ctx->sio_comp_ids.user_conn_entity,
        };
        shift_collection_info_t ci = {
            .name       = "sio_write_results",
            .comp_ids   = comps,
            .comp_count = sizeof(comps) / sizeof(comps[0]),
        };
        if (shift_collection_register(ctx->shift, &ci,
                                      &ctx->sio_write_results) != shift_ok) {
            free(ctx);
            return sh2_error_invalid;
        }
    }

    /* create sio context */
    {
        sio_config_t sio_cfg = {
            .shift              = ctx->shift,
            .comp_ids           = ctx->sio_comp_ids,
            .buf_count          = cfg->buf_count,
            .buf_size           = cfg->buf_size,
            .max_connections    = cfg->max_connections,
            .ring_entries       = cfg->ring_entries,
            .connection_results = ctx->sio_connection_results,
            .read_results       = ctx->sio_read_results,
            .write_results      = ctx->sio_write_results,
            .auto_destroy_user_entity = false,
            .ring_params        = cfg->ring_params,
        };
        if (sio_context_create(&sio_cfg, &ctx->sio) != sio_ok) {
            free(ctx);
            return sh2_error_io;
        }
    }

    /* internal collection: response_sending */
    {
        shift_component_id_t comps[] = {
            cfg->comp_ids.stream_id,  cfg->comp_ids.session,
            cfg->comp_ids.req_headers, cfg->comp_ids.req_body,
            cfg->comp_ids.resp_headers, cfg->comp_ids.resp_body,
            cfg->comp_ids.status,     cfg->comp_ids.io_result,
            cfg->comp_ids.domain_tag,
        };
        shift_collection_info_t ci = {
            .name       = "response_sending",
            .comp_ids   = comps,
            .comp_count = sizeof(comps) / sizeof(comps[0]),
        };
        if (shift_collection_register(ctx->shift, &ci,
                                      &ctx->coll_response_sending) != shift_ok) {
            sio_context_destroy(ctx->sio);
            free(ctx);
            return sh2_error_invalid;
        }
    }

    /* internal read processing collections (same archetype as sio_read_results) */
    {
        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.read_buf,
            ctx->sio_comp_ids.io_result,
            ctx->sio_comp_ids.conn_entity,
            ctx->sio_comp_ids.user_conn_entity,
        };
        shift_collection_info_t ci_err  = { .name = "read_errors",  .comp_ids = comps,
                                            .comp_count = sizeof(comps) / sizeof(comps[0]) };
        shift_collection_info_t ci_init = { .name = "read_init",    .comp_ids = comps,
                                            .comp_count = sizeof(comps) / sizeof(comps[0]) };
        shift_collection_info_t ci_act  = { .name = "read_active",  .comp_ids = comps,
                                            .comp_count = sizeof(comps) / sizeof(comps[0]) };
        if (shift_collection_register(ctx->shift, &ci_err,
                                      &ctx->coll_read_errors) != shift_ok ||
            shift_collection_register(ctx->shift, &ci_init,
                                      &ctx->coll_read_init) != shift_ok ||
            shift_collection_register(ctx->shift, &ci_act,
                                      &ctx->coll_read_active) != shift_ok) {
            sio_context_destroy(ctx->sio);
            free(ctx);
            return sh2_error_invalid;
        }
    }

    /* connections array */
    ctx->max_connections = cfg->max_connections;
    ctx->conns = calloc(cfg->max_connections, sizeof(sh2_conn_t));
    if (!ctx->conns) {
        sio_context_destroy(ctx->sio);
        free(ctx);
        return sh2_error_oom;
    }

    /* nghttp2 callbacks */
    sh2_result_t r = sh2_nghttp2_init_callbacks(ctx);
    if (r != sh2_ok) {
        sio_context_destroy(ctx->sio);
        free(ctx->conns);
        free(ctx);
        return r;
    }

#ifdef SH2_HAS_TLS
    if (cfg->tls) {
        ctx->tls_config = cfg->tls;

        /* TLS handshake collection (same archetype as read results) */
        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.read_buf,
            ctx->sio_comp_ids.io_result,
            ctx->sio_comp_ids.conn_entity,
            ctx->sio_comp_ids.user_conn_entity,
        };
        shift_collection_info_t ci = {
            .name       = "read_tls_handshake",
            .comp_ids   = comps,
            .comp_count = sizeof(comps) / sizeof(comps[0]),
        };
        if (shift_collection_register(ctx->shift, &ci,
                                      &ctx->coll_read_handshake) != shift_ok) {
            sio_context_destroy(ctx->sio);
            free(ctx->conns);
            nghttp2_session_callbacks_del(ctx->ng_callbacks);
            free(ctx);
            return sh2_error_invalid;
        }

        r = sh2_tls_init(ctx);
        if (r != sh2_ok) {
            sio_context_destroy(ctx->sio);
            free(ctx->conns);
            nghttp2_session_callbacks_del(ctx->ng_callbacks);
            free(ctx);
            return r;
        }
    }
#endif

    *out = ctx;
    return sh2_ok;
}

void sh2_context_destroy(sh2_context_t *ctx) {
    if (!ctx) return;

    for (uint32_t i = 0; i < ctx->max_connections; i++) {
#ifdef SH2_HAS_TLS
        sh2_tls_conn_destroy(ctx, i);
#endif
        if (ctx->conns[i].ng_session)
            sh2_nghttp2_session_destroy(ctx, i);
    }

    shift_flush(ctx->shift);
    {
        shift_entity_t *entities = NULL;
        size_t          count    = 0;
        shift_collection_get_entities(ctx->shift, ctx->coll_response_sending,
                                      &entities, &count);
        for (size_t i = 0; i < count; i++)
            shift_entity_destroy_one(ctx->shift, entities[i]);
        shift_flush(ctx->shift);
    }

    sio_context_destroy(ctx->sio);

#ifdef SH2_HAS_TLS
    sh2_tls_cleanup(ctx);
#endif

    if (ctx->ng_callbacks)
        nghttp2_session_callbacks_del(ctx->ng_callbacks);

    free(ctx->conns);
    free(ctx);
}

/* --------------------------------------------------------------------------
 * sh2_listen
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_listen(sh2_context_t *ctx, uint16_t port, int backlog) {
    if (!ctx) return sh2_error_null;
    return sio_listen(ctx->sio, port, backlog) == sio_ok
        ? sh2_ok : sh2_error_io;
}

/* --------------------------------------------------------------------------
 * Accessors
 * -------------------------------------------------------------------------- */

const sh2_component_ids_t *sh2_get_component_ids(const sh2_context_t *ctx) {
    return ctx ? &ctx->comp_ids : NULL;
}

const sh2_collection_ids_t *sh2_get_collection_ids(const sh2_context_t *ctx) {
    return ctx ? &ctx->coll_ids : NULL;
}
