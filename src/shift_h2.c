#include "shift_h2_internal.h"
#include "sh2_nghttp2.h"
#include "sh2_nghttp2_client.h"

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

static void peer_cert_dtor(shift_t *ctx, shift_collection_id_t col_id,
                           const shift_entity_t *entities, void *data,
                           uint32_t offset, uint32_t count, void *user_data) {
    (void)ctx; (void)col_id; (void)entities; (void)user_data;
    sh2_peer_cert_t *pcs = (sh2_peer_cert_t *)data + offset;
    for (uint32_t i = 0; i < count; i++) {
        free(pcs[i].subject_cn);
        free(pcs[i].subject_dn);
        free(pcs[i].issuer_dn);
        free(pcs[i].serial_hex);
        pcs[i] = (sh2_peer_cert_t){0};
    }
}

/* Connection component destructor — safety net for cleanup.
 * In the normal path, ng_session is already NULL (session_destroy was called
 * during draining).  This catches orphaned entities. */
static void conn_dtor(shift_t *ctx, shift_collection_id_t col_id,
                      const shift_entity_t *entities, void *data,
                      uint32_t offset, uint32_t count, void *user_data) {
    (void)ctx; (void)col_id; (void)entities; (void)user_data;
    sh2_conn_t *conns = (sh2_conn_t *)data + offset;
    for (uint32_t i = 0; i < count; i++) {
        if (conns[i].ng_session) {
            nghttp2_session_del(conns[i].ng_session);
            conns[i].ng_session = NULL;
        }
        free(conns[i].ng_ctx);
        conns[i].ng_ctx = NULL;
        free(conns[i].hostname);
        conns[i].hostname = NULL;
#ifdef SH2_HAS_TLS
        if (conns[i].tls) {
            SSL_free(conns[i].tls->ssl);
            free(conns[i].tls);
            conns[i].tls = NULL;
        }
#endif
    }
}

/* Hostname component destructor */
static void hostname_dtor(shift_t *ctx, shift_collection_id_t col_id,
                          const shift_entity_t *entities, void *data,
                          uint32_t offset, uint32_t count, void *user_data) {
    (void)ctx; (void)col_id; (void)entities; (void)user_data;
    sh2_hostname_t *hs = (sh2_hostname_t *)data + offset;
    for (uint32_t i = 0; i < count; i++) {
        free(hs[i].hostname);
        hs[i].hostname = NULL;
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
    REG_EX(peer_cert, sh2_peer_cert_t, peer_cert_dtor)
    REG(connect_target, sh2_connect_target_t)

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
    ctx->coll_ids.response_out = cfg->response_out;

    /* register sio components */
    if (sio_register_components(ctx->shift, &ctx->sio_comp_ids) != sio_ok) {
        free(ctx);
        return sh2_error_invalid;
    }

    /* register internal connection component (sh2_conn_t) with destructor */
    {
        shift_component_info_t ci = {
            .element_size = sizeof(sh2_conn_t),
            .destructor   = conn_dtor,
        };
        if (shift_component_register(ctx->shift, &ci,
                                      &ctx->internal_conn) != shift_ok) {
            free(ctx);
            return sh2_error_invalid;
        }
    }

    /* register internal hostname component for connect entities */
    {
        shift_component_info_t ci = {
            .element_size = sizeof(sh2_hostname_t),
            .destructor   = hostname_dtor,
        };
        if (shift_component_register(ctx->shift, &ci,
                                      &ctx->internal_hostname) != shift_ok) {
            free(ctx);
            return sh2_error_invalid;
        }
    }

    /* create sio result collections — connection_results now carries
     * the internal_conn component so sio's connections collection
     * (via superset) also has it. */
    {
        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.conn_entity,
            ctx->internal_conn,
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

    /* sio connect_results collection (if outgoing connections enabled) */
    ctx->enable_connect = cfg->enable_connect;
    if (cfg->enable_connect) {
        ctx->coll_ids_client = cfg->client_colls;

        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.io_result,
            ctx->sio_comp_ids.conn_entity,
            ctx->sio_comp_ids.user_conn_entity,
            ctx->internal_hostname,
        };
        shift_collection_info_t ci = {
            .name       = "sio_connect_results",
            .comp_ids   = comps,
            .comp_count = sizeof(comps) / sizeof(comps[0]),
        };
        if (shift_collection_register(ctx->shift, &ci,
                                      &ctx->sio_connect_results) != shift_ok) {
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
            .enable_connect     = cfg->enable_connect,
            .connect_results    = ctx->sio_connect_results,
        };
        if (sio_context_create(&sio_cfg, &ctx->sio) != sio_ok) {
            free(ctx);
            return sh2_error_io;
        }
    }

    /* internal collection: response_sending
     * Mirror response_in's component list so user-added components
     * survive the response_in → response_sending → response_out
     * pipeline without being destructed. */
    {
        const shift_component_id_t *resp_comps = NULL;
        uint32_t resp_comp_count = 0;
        if (shift_collection_get_components(ctx->shift,
                ctx->coll_ids.response_in,
                &resp_comps, &resp_comp_count) != shift_ok) {
            sio_context_destroy(ctx->sio);
            free(ctx);
            return sh2_error_invalid;
        }
        shift_collection_info_t ci = {
            .name       = "response_sending",
            .comp_ids   = resp_comps,
            .comp_count = resp_comp_count,
        };
        if (shift_collection_register(ctx->shift, &ci,
                                      &ctx->coll_response_sending) != shift_ok) {
            sio_context_destroy(ctx->sio);
            free(ctx);
            return sh2_error_invalid;
        }
    }

    /* connection state collections (same archetype as sio_connection_results) */
    {
        shift_component_id_t comps[] = {
            ctx->sio_comp_ids.conn_entity,
            ctx->internal_conn,
        };
        uint32_t ncomps = sizeof(comps) / sizeof(comps[0]);
        shift_collection_info_t ci_active = { .name = "conn_active",
            .comp_ids = comps, .comp_count = ncomps };
        shift_collection_info_t ci_hs = { .name = "conn_tls_handshake",
            .comp_ids = comps, .comp_count = ncomps };
        shift_collection_info_t ci_drain = { .name = "conn_draining",
            .comp_ids = comps, .comp_count = ncomps };
        if (shift_collection_register(ctx->shift, &ci_active,
                                      &ctx->coll_conn_active) != shift_ok ||
            shift_collection_register(ctx->shift, &ci_hs,
                                      &ctx->coll_conn_tls_handshake) != shift_ok ||
            shift_collection_register(ctx->shift, &ci_drain,
                                      &ctx->coll_conn_draining) != shift_ok) {
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

    ctx->max_connections = cfg->max_connections;

    /* nghttp2 server callbacks */
    sh2_result_t r = sh2_nghttp2_init_callbacks(ctx);
    if (r != sh2_ok) {
        sio_context_destroy(ctx->sio);
        free(ctx);
        return r;
    }

    /* client-path setup (if outgoing connections enabled) */
    if (cfg->enable_connect) {
        /* client nghttp2 callbacks */
        r = sh2_nghttp2_client_init_callbacks(ctx);
        if (r != sh2_ok) {
            sio_context_destroy(ctx->sio);
            nghttp2_session_callbacks_del(ctx->ng_callbacks);
            free(ctx);
            return r;
        }

        /* client internal collections */
        {
            shift_component_id_t comps[] = {
                cfg->comp_ids.stream_id,  cfg->comp_ids.session,
                cfg->comp_ids.req_headers, cfg->comp_ids.req_body,
                cfg->comp_ids.resp_headers, cfg->comp_ids.resp_body,
                cfg->comp_ids.status,     cfg->comp_ids.io_result,
                cfg->comp_ids.domain_tag, cfg->comp_ids.peer_cert,
            };
            shift_collection_info_t ci = {
                .name       = "client_request_sending",
                .comp_ids   = comps,
                .comp_count = sizeof(comps) / sizeof(comps[0]),
            };
            if (shift_collection_register(ctx->shift, &ci,
                                          &ctx->coll_client_request_sending) != shift_ok) {
                sio_context_destroy(ctx->sio);
                nghttp2_session_callbacks_del(ctx->ng_callbacks);
                nghttp2_session_callbacks_del(ctx->ng_client_callbacks);
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
            shift_collection_info_t ci_init = { .name = "read_client_init",
                                                .comp_ids = comps,
                                                .comp_count = sizeof(comps) / sizeof(comps[0]) };
            shift_collection_info_t ci_hs   = { .name = "read_client_handshake",
                                                .comp_ids = comps,
                                                .comp_count = sizeof(comps) / sizeof(comps[0]) };
            if (shift_collection_register(ctx->shift, &ci_init,
                                          &ctx->coll_read_client_init) != shift_ok ||
                shift_collection_register(ctx->shift, &ci_hs,
                                          &ctx->coll_read_client_handshake) != shift_ok) {
                sio_context_destroy(ctx->sio);
                nghttp2_session_callbacks_del(ctx->ng_callbacks);
                nghttp2_session_callbacks_del(ctx->ng_client_callbacks);
                free(ctx);
                return sh2_error_invalid;
            }
        }
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
            nghttp2_session_callbacks_del(ctx->ng_callbacks);
            free(ctx);
            return sh2_error_invalid;
        }

        r = sh2_tls_init(ctx);
        if (r != sh2_ok) {
            sio_context_destroy(ctx->sio);
            nghttp2_session_callbacks_del(ctx->ng_callbacks);
            free(ctx);
            return r;
        }
    }

    if (cfg->enable_connect && cfg->tls_client) {
        ctx->tls_client_config = cfg->tls_client;
        r = sh2_tls_client_init(ctx);
        if (r != sh2_ok) {
            sio_context_destroy(ctx->sio);
            nghttp2_session_callbacks_del(ctx->ng_callbacks);
            if (ctx->ng_client_callbacks)
                nghttp2_session_callbacks_del(ctx->ng_client_callbacks);
            if (ctx->ssl_ctx) sh2_tls_cleanup(ctx);
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

    /* Tear down connections in state collections.
     * The conn_dtor destructor handles cleanup as a safety net, but we
     * do controlled shutdown (nghttp2 terminate + flush) first. */
    {
        shift_collection_id_t state_colls[] = {
            ctx->coll_conn_active,
            ctx->coll_conn_tls_handshake,
            ctx->coll_conn_draining,
        };
        for (uint32_t c = 0; c < sizeof(state_colls) / sizeof(state_colls[0]); c++) {
            shift_entity_t *entities = NULL;
            size_t count = 0;
            shift_collection_get_entities(ctx->shift, state_colls[c],
                                          &entities, &count);
            for (size_t i = 0; i < count; i++) {
                sh2_conn_t *conn = sh2_conn_get(ctx, entities[i]);
                if (!conn) continue;
#ifdef SH2_HAS_TLS
                sh2_tls_conn_destroy(conn);
#endif
                if (conn->ng_session)
                    sh2_nghttp2_session_destroy(ctx, entities[i]);
            }
        }
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

    if (ctx->enable_connect) {
        shift_entity_t *entities = NULL;
        size_t          count    = 0;
        shift_collection_get_entities(ctx->shift, ctx->coll_client_request_sending,
                                      &entities, &count);
        for (size_t i = 0; i < count; i++)
            shift_entity_destroy_one(ctx->shift, entities[i]);
        shift_flush(ctx->shift);
    }

    sio_context_destroy(ctx->sio);

#ifdef SH2_HAS_TLS
    sh2_tls_cleanup(ctx);
    sh2_tls_client_cleanup(ctx);
#endif

    if (ctx->ng_callbacks)
        nghttp2_session_callbacks_del(ctx->ng_callbacks);
    if (ctx->ng_client_callbacks)
        nghttp2_session_callbacks_del(ctx->ng_client_callbacks);

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

const sh2_client_collection_ids_t *sh2_get_client_collection_ids(const sh2_context_t *ctx) {
    return (ctx && ctx->enable_connect) ? &ctx->coll_ids_client : NULL;
}
