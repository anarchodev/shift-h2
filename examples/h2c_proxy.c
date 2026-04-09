#define _GNU_SOURCE

#include <shift_h2.h>
#include <shift.h>

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LISTEN_PORT     8080
#define BACKLOG         1024
#define MAX_CONNECTIONS 1024
#define MAX_STREAMS     (MAX_CONNECTIONS * 128)
#define BUF_COUNT       4096
#define BUF_SIZE        (64 * 1024)
#define RING_ENTRIES    4096

static volatile int g_running = 1;
static void handle_signal(int sig) { (void)sig; g_running = 0; }

/* ---- Custom component: cross-reference between paired entities ---- */
typedef struct {
    shift_entity_t peer;
} proxy_peer_t;

/* ---- Proxy context (replaces loose variables) ---- */
typedef struct {
    shift_t                    *sh;
    sh2_component_ids_t         comp;
    shift_component_id_t        proxy_peer;

    /* sh2-owned collections */
    shift_collection_id_t       request_out;
    shift_collection_id_t       response_in;
    shift_collection_id_t       response_out;

    /* proxy-owned collections */
    shift_collection_id_t       pending;       /* parked pre-connect */
    shift_collection_id_t       inflight;      /* forwarded, awaiting response */

    /* client-side collections */
    shift_collection_id_t       connect_in;
    shift_collection_id_t       connect_out;
    shift_collection_id_t       connect_errors;
    shift_collection_id_t       disconnect_in;
    shift_collection_id_t       client_request_in;
    shift_collection_id_t       client_cancel_in;
    shift_collection_id_t       client_response_out;

    /* backend state */
    shift_entity_t              backend_session;
    bool                        backend_connecting;
    const char                 *backend_host;
    uint16_t                    backend_port;
    struct sockaddr_in          backend_addr;
} proxy_t;

static bool backend_connected(const proxy_t *p) {
    return !shift_entity_is_stale(p->sh, p->backend_session);
}

/* ---- Create a client request entity from a server request entity ---- */
static shift_entity_t submit_upstream(proxy_t *p, shift_entity_t server_e) {
    sh2_req_headers_t *rqh = NULL;
    sh2_req_body_t    *rqb = NULL;
    shift_entity_get_component(p->sh, server_e, p->comp.req_headers,
                               (void **)&rqh);
    shift_entity_get_component(p->sh, server_e, p->comp.req_body,
                               (void **)&rqb);

    shift_entity_t client_e;
    shift_entity_create_one_begin(p->sh, p->client_request_in, &client_e);

    /* bind to backend session */
    sh2_session_t *rsess = NULL;
    shift_entity_get_component(p->sh, client_e, p->comp.session,
                               (void **)&rsess);
    rsess->entity = p->backend_session;

    /* copy request headers, replacing :authority */
    sh2_header_field_t *fields = calloc(rqh->count, sizeof(sh2_header_field_t));
    for (uint32_t j = 0; j < rqh->count; j++) {
        const sh2_header_field_t *f = &rqh->fields[j];
        if (f->name_len == 10 && memcmp(f->name, ":authority", 10) == 0) {
            char *auth = malloc(strlen(p->backend_host) + 8);
            int auth_len = sprintf(auth, "%s:%u",
                                   p->backend_host, p->backend_port);
            fields[j] = (sh2_header_field_t){
                .name = strdup(":authority"), .name_len = 10,
                .value = auth, .value_len = (uint32_t)auth_len,
            };
        } else {
            char *n = malloc(f->name_len);
            char *v = malloc(f->value_len);
            memcpy(n, f->name, f->name_len);
            memcpy(v, f->value, f->value_len);
            fields[j] = (sh2_header_field_t){
                .name = n, .name_len = f->name_len,
                .value = v, .value_len = f->value_len,
            };
        }
    }

    sh2_req_headers_t *crh = NULL;
    shift_entity_get_component(p->sh, client_e, p->comp.req_headers,
                               (void **)&crh);
    crh->fields = fields;
    crh->count  = rqh->count;

    /* copy request body */
    if (rqb && rqb->data && rqb->len > 0) {
        sh2_req_body_t *crb = NULL;
        shift_entity_get_component(p->sh, client_e, p->comp.req_body,
                                   (void **)&crb);
        crb->data = malloc(rqb->len);
        memcpy(crb->data, rqb->data, rqb->len);
        crb->len = rqb->len;
    }

    shift_entity_create_one_end(p->sh, client_e);
    return client_e;
}

/* ---- System 1: consume connect results ---- */
static void system_connect(proxy_t *p) {
    if (!p->backend_connecting) return;

    shift_entity_t *entities = NULL;
    size_t count = 0;
    shift_collection_get_entities(p->sh, p->connect_out, &entities, &count);

    for (size_t i = 0; i < count; i++) {
        sh2_session_t *sess = NULL;
        shift_entity_get_component(p->sh, entities[i], p->comp.session,
                                   (void **)&sess);
        p->backend_session = sess->entity;
        p->backend_connecting = false;
        printf("Backend connected!\n");
        shift_entity_destroy_one(p->sh, entities[i]);
    }

    /* drain connect errors */
    shift_collection_get_entities(p->sh, p->connect_errors, &entities, &count);
    for (size_t i = 0; i < count; i++) {
        sh2_io_result_t *io = NULL;
        shift_entity_get_component(p->sh, entities[i], p->comp.io_result,
                                   (void **)&io);
        fprintf(stderr, "Backend connect failed: %d\n",
                io ? io->error : -1);
        p->backend_connecting = false;
        shift_entity_destroy_one(p->sh, entities[i]);
    }
}

/* ---- System 2: accept incoming requests ---- */
static void system_accept_requests(proxy_t *p) {
    shift_entity_t *entities = NULL;
    size_t count = 0;
    shift_collection_get_entities(p->sh, p->request_out, &entities, &count);

    for (size_t i = 0; i < count; i++)
        shift_entity_move_one(p->sh, entities[i], p->pending);
}

/* ---- System 3: flush pending requests once backend connects ---- */
static void system_flush_pending(proxy_t *p) {
    if (!backend_connected(p)) return;

    shift_entity_t *entities = NULL;
    size_t count = 0;
    shift_collection_get_entities(p->sh, p->pending, &entities, &count);

    for (size_t i = 0; i < count; i++) {
        shift_entity_t client_e = submit_upstream(p, entities[i]);

        /* set cross-reference: server → client.
         * Entity is in pending (has proxy_peer). Client entity travels
         * through sh2 internal collections that lack proxy_peer, so the
         * reference must live on the server side. */
        proxy_peer_t *pp = NULL;
        shift_entity_get_component(p->sh, entities[i], p->proxy_peer,
                                   (void **)&pp);
        pp->peer = client_e;

        shift_entity_move_one(p->sh, entities[i], p->inflight);
    }
}

/* ---- System 4: map upstream responses back to downstream ---- */
static void system_map_responses(proxy_t *p) {
    shift_entity_t *entities = NULL;
    size_t count = 0;
    shift_collection_get_entities(p->sh, p->client_response_out,
                                  &entities, &count);

    /* get inflight server entities and their peer components for scanning */
    shift_entity_t *inflight_ents = NULL;
    proxy_peer_t   *inflight_peers = NULL;
    size_t          inflight_count = 0;
    shift_collection_get_entities(p->sh, p->inflight,
                                  &inflight_ents, &inflight_count);
    if (inflight_count > 0)
        shift_collection_get_component_array(p->sh, p->inflight, p->proxy_peer,
                                             (void **)&inflight_peers, NULL);

    for (size_t i = 0; i < count; i++) {
        shift_entity_t client_e = entities[i];

        /* scan inflight for the server entity whose peer matches client_e */
        shift_entity_t server_e = {0};
        for (size_t j = 0; j < inflight_count; j++) {
            if (inflight_peers[j].peer.index == client_e.index &&
                inflight_peers[j].peer.generation == client_e.generation) {
                server_e = inflight_ents[j];
                break;
            }
        }
        if (server_e.index == 0 && server_e.generation == 0) {
            fprintf(stderr, "proxy: orphan response (no matching inflight)\n");
            shift_entity_destroy_one(p->sh, client_e);
            continue;
        }

        /* extract upstream response */
        sh2_status_t *ust = NULL;
        shift_entity_get_component(p->sh, client_e, p->comp.status,
                                   (void **)&ust);
        sh2_resp_headers_t *urh = NULL;
        shift_entity_get_component(p->sh, client_e, p->comp.resp_headers,
                                   (void **)&urh);
        sh2_resp_body_t *urb = NULL;
        shift_entity_get_component(p->sh, client_e, p->comp.resp_body,
                                   (void **)&urb);
        sh2_io_result_t *uio = NULL;
        shift_entity_get_component(p->sh, client_e, p->comp.io_result,
                                   (void **)&uio);

        if (uio && uio->error != 0) {
            fprintf(stderr, "proxy: upstream error %d, sending 502\n",
                    uio->error);

            sh2_status_t *st = NULL;
            shift_entity_get_component(p->sh, server_e, p->comp.status,
                                       (void **)&st);
            st->code = 502;

            sh2_resp_headers_t *rh = NULL;
            shift_entity_get_component(p->sh, server_e, p->comp.resp_headers,
                                       (void **)&rh);
            rh->fields = NULL;
            rh->count  = 0;

            sh2_resp_body_t *rb = NULL;
            shift_entity_get_component(p->sh, server_e, p->comp.resp_body,
                                       (void **)&rb);
            rb->data = strdup("Bad Gateway\n");
            rb->len  = 12;

            shift_entity_move_one(p->sh, server_e, p->response_in);
            shift_entity_destroy_one(p->sh, client_e);
            continue;
        }

        /* copy status */
        sh2_status_t *st = NULL;
        shift_entity_get_component(p->sh, server_e, p->comp.status,
                                   (void **)&st);
        st->code = ust ? ust->code : 502;

        /* copy response headers */
        sh2_resp_headers_t *rh = NULL;
        shift_entity_get_component(p->sh, server_e, p->comp.resp_headers,
                                   (void **)&rh);
        if (urh && urh->count > 0) {
            sh2_header_field_t *dst = malloc(urh->count * sizeof(*dst));
            for (uint32_t j = 0; j < urh->count; j++) {
                char *n = malloc(urh->fields[j].name_len);
                char *v = malloc(urh->fields[j].value_len);
                memcpy(n, urh->fields[j].name, urh->fields[j].name_len);
                memcpy(v, urh->fields[j].value, urh->fields[j].value_len);
                dst[j] = (sh2_header_field_t){
                    .name = n, .name_len = urh->fields[j].name_len,
                    .value = v, .value_len = urh->fields[j].value_len,
                };
            }
            rh->fields = dst;
            rh->count  = urh->count;
        } else {
            rh->fields = NULL;
            rh->count  = 0;
        }

        /* copy response body */
        sh2_resp_body_t *rb = NULL;
        shift_entity_get_component(p->sh, server_e, p->comp.resp_body,
                                   (void **)&rb);
        if (urb && urb->data && urb->len > 0) {
            rb->data = malloc(urb->len);
            memcpy(rb->data, urb->data, urb->len);
            rb->len = urb->len;
        } else {
            rb->data = NULL;
            rb->len  = 0;
        }

        /* moves last */
        shift_entity_move_one(p->sh, server_e, p->response_in);
        shift_entity_destroy_one(p->sh, client_e);
    }
}

/* ---- System 5: drain sent responses ---- */
static void system_drain_sent(proxy_t *p) {
    shift_entity_t *entities = NULL;
    size_t count = 0;
    shift_collection_get_entities(p->sh, p->response_out, &entities, &count);

    for (size_t i = 0; i < count; i++) {
        sh2_io_result_t *io = NULL;
        shift_entity_get_component(p->sh, entities[i], p->comp.io_result,
                                   (void **)&io);
        if (io && io->error != 0)
            fprintf(stderr, "proxy: downstream send failed: %d\n", io->error);
        shift_entity_destroy_one(p->sh, entities[i]);
    }
}

/* ---- System 6: reconnect if backend disconnected ---- */
static void system_reconnect(proxy_t *p) {
    if (backend_connected(p) || p->backend_connecting)
        return;

    shift_entity_t ce;
    shift_entity_create_one_begin(p->sh, p->connect_in, &ce);
    sh2_connect_target_t *tgt = NULL;
    shift_entity_get_component(p->sh, ce, p->comp.connect_target,
                               (void **)&tgt);
    tgt->addr         = p->backend_addr;
    tgt->hostname     = p->backend_host;
    tgt->hostname_len = (uint32_t)strlen(p->backend_host);
    shift_entity_create_one_end(p->sh, ce);
    p->backend_connecting = true;
    printf("Reconnecting to backend...\n");
}

int main(int argc, char **argv) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    proxy_t p = {0};
    p.backend_host = "127.0.0.1";
    p.backend_port = 9000;
    uint16_t listen_port = LISTEN_PORT;
    if (argc > 1) p.backend_host = argv[1];
    if (argc > 2) p.backend_port = (uint16_t)atoi(argv[2]);
    if (argc > 3) listen_port    = (uint16_t)atoi(argv[3]);

    printf("h2c reverse proxy: :%u -> %s:%u\n",
           listen_port, p.backend_host, p.backend_port);

    /* ---- shift context ---- */
    shift_config_t sh_cfg = {
        .max_entities            = MAX_CONNECTIONS * 16 + MAX_STREAMS + 1024,
        .max_components          = 32,
        .max_collections         = 64,
        .deferred_queue_capacity = MAX_CONNECTIONS * 256,
    };
    if (shift_context_create(&sh_cfg, &p.sh) != shift_ok) {
        fprintf(stderr, "shift_context_create failed\n");
        return 1;
    }

    /* ---- register sh2 components ---- */
    if (sh2_register_components(p.sh, &p.comp) != sh2_ok) {
        fprintf(stderr, "sh2_register_components failed\n");
        shift_context_destroy(p.sh);
        return 1;
    }

    /* ---- register proxy_peer component ---- */
    shift_component_info_t peer_info = {
        .element_size = sizeof(proxy_peer_t),
    };
    if (shift_component_register(p.sh, &peer_info, &p.proxy_peer) != shift_ok) {
        fprintf(stderr, "failed to register proxy_peer component\n");
        shift_context_destroy(p.sh);
        return 1;
    }

    /* ---- collections ---- */
    /* sh2-facing collections use sh2 components only */
    shift_component_id_t sh2_comps[] = {
        p.comp.stream_id, p.comp.session, p.comp.req_headers, p.comp.req_body,
        p.comp.resp_headers, p.comp.resp_body, p.comp.status, p.comp.io_result,
        p.comp.domain_tag, p.comp.peer_cert,
    };
    const size_t sh2_comps_count = sizeof(sh2_comps) / sizeof(sh2_comps[0]);

    /* proxy-owned collections add proxy_peer for cross-referencing */
    shift_component_id_t proxy_comps[] = {
        p.comp.stream_id, p.comp.session, p.comp.req_headers, p.comp.req_body,
        p.comp.resp_headers, p.comp.resp_body, p.comp.status, p.comp.io_result,
        p.comp.domain_tag, p.comp.peer_cert, p.proxy_peer,
    };
    const size_t proxy_comps_count = sizeof(proxy_comps) / sizeof(proxy_comps[0]);

    shift_component_id_t connect_in_comps[] = {
        p.comp.connect_target,
    };
    shift_component_id_t connect_out_comps[] = {
        p.comp.connect_target, p.comp.session,
    };
    shift_component_id_t connect_err_comps[] = {
        p.comp.connect_target, p.comp.io_result,
    };

    {
        shift_collection_info_t colls[] = {
            { .name = "request_out",          .comp_ids = sh2_comps,   .comp_count = sh2_comps_count },
            { .name = "response_in",          .comp_ids = sh2_comps,   .comp_count = sh2_comps_count },
            { .name = "response_out",         .comp_ids = sh2_comps,   .comp_count = sh2_comps_count },
            { .name = "pending",              .comp_ids = proxy_comps, .comp_count = proxy_comps_count },
            { .name = "inflight",             .comp_ids = proxy_comps, .comp_count = proxy_comps_count },
            { .name = "connect_in",           .comp_ids = connect_in_comps,
              .comp_count = sizeof(connect_in_comps) / sizeof(connect_in_comps[0]) },
            { .name = "connect_out",          .comp_ids = connect_out_comps,
              .comp_count = sizeof(connect_out_comps) / sizeof(connect_out_comps[0]) },
            { .name = "connect_errors",       .comp_ids = connect_err_comps,
              .comp_count = sizeof(connect_err_comps) / sizeof(connect_err_comps[0]) },
            { .name = "disconnect_in",        .comp_ids = sh2_comps,   .comp_count = sh2_comps_count },
            { .name = "client_request_in",    .comp_ids = sh2_comps,   .comp_count = sh2_comps_count },
            { .name = "client_cancel_in",     .comp_ids = sh2_comps,   .comp_count = sh2_comps_count },
            { .name = "client_response_out",  .comp_ids = sh2_comps,   .comp_count = sh2_comps_count },
        };
        shift_collection_id_t *ids[] = {
            &p.request_out, &p.response_in, &p.response_out,
            &p.pending, &p.inflight,
            &p.connect_in, &p.connect_out, &p.connect_errors, &p.disconnect_in,
            &p.client_request_in, &p.client_cancel_in, &p.client_response_out,
        };
        for (int c = 0; c < 12; c++) {
            if (shift_collection_register(p.sh, &colls[c], ids[c]) != shift_ok) {
                fprintf(stderr, "failed to register collection: %s\n",
                        colls[c].name);
                shift_context_destroy(p.sh);
                return 1;
            }
        }
    }

    /* ---- create sh2 context ---- */
    sh2_context_t *ctx = NULL;
    sh2_config_t cfg = {
        .shift               = p.sh,
        .comp_ids            = p.comp,
        .max_connections     = MAX_CONNECTIONS,
        .ring_entries        = RING_ENTRIES,
        .buf_count           = BUF_COUNT,
        .buf_size            = BUF_SIZE,
        .request_out         = p.request_out,
        .response_in         = p.response_in,
        .response_out        = p.response_out,
        .enable_connect      = true,
        .client_colls = {
            .connect_in      = p.connect_in,
            .connect_out     = p.connect_out,
            .connect_errors  = p.connect_errors,
            .disconnect_in   = p.disconnect_in,
            .request_in      = p.client_request_in,
            .cancel_in       = p.client_cancel_in,
            .response_out    = p.client_response_out,
        },
    };
    sh2_result_t r = sh2_context_create(&cfg, &ctx);
    if (r != sh2_ok) {
        fprintf(stderr, "sh2_context_create failed: %d (errno=%d: %s)\n",
                r, errno, strerror(errno));
        shift_context_destroy(p.sh);
        return 1;
    }

    if (sh2_listen(ctx, listen_port, BACKLOG) != sh2_ok) {
        fprintf(stderr, "sh2_listen failed on port %u\n", listen_port);
        sh2_context_destroy(ctx);
        shift_context_destroy(p.sh);
        return 1;
    }

    printf("Listening on port %u\n", listen_port);

    /* ---- backend target address ---- */
    p.backend_addr = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port   = htons(p.backend_port),
    };
    inet_pton(AF_INET, p.backend_host, &p.backend_addr.sin_addr);

    /* ---- initiate backend connection ---- */
    {
        shift_entity_t ce;
        shift_entity_create_one_begin(p.sh, p.connect_in, &ce);
        sh2_connect_target_t *tgt = NULL;
        shift_entity_get_component(p.sh, ce, p.comp.connect_target,
                                   (void **)&tgt);
        tgt->addr         = p.backend_addr;
        tgt->hostname     = p.backend_host;
        tgt->hostname_len = (uint32_t)strlen(p.backend_host);
        shift_entity_create_one_end(p.sh, ce);
        p.backend_connecting = true;
        printf("Connecting to backend %s:%u...\n", p.backend_host, p.backend_port);
    }

    /* ---- event loop ---- */
    while (g_running) {
        if (sh2_poll(ctx, 0) != sh2_ok)
            break;

        system_connect(&p);
        shift_flush(p.sh);

        system_accept_requests(&p);
        shift_flush(p.sh);

        system_flush_pending(&p);
        shift_flush(p.sh);

        system_map_responses(&p);
        shift_flush(p.sh);

        system_drain_sent(&p);
        shift_flush(p.sh);

        system_reconnect(&p);
        shift_flush(p.sh);
    }

    /* ---- shutdown ---- */
    sh2_context_destroy(ctx);
    shift_flush(p.sh);

    shift_collection_id_t drain_cols[] = {
        p.request_out, p.response_in, p.response_out,
        p.pending, p.inflight,
    };
    for (int c = 0; c < 5; c++) {
        shift_entity_t *entities = NULL;
        size_t count = 0;
        shift_collection_get_entities(p.sh, drain_cols[c], &entities, &count);
        for (size_t i = 0; i < count; i++)
            shift_entity_destroy_one(p.sh, entities[i]);
    }
    shift_flush(p.sh);

    shift_context_destroy(p.sh);
    printf("\nProxy shutdown complete.\n");
    return 0;
}
