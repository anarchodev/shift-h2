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

#define MAX_CONNECTIONS 64
#define BUF_COUNT       256
#define BUF_SIZE        (64 * 1024)
#define RING_ENTRIES    256

static volatile int g_running = 1;
static void handle_signal(int sig) { (void)sig; g_running = 0; }

int main(int argc, char **argv) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    const char *host = "127.0.0.1";
    uint16_t    port = 9000;
    const char *path = "/";
    if (argc > 1) host = argv[1];
    if (argc > 2) port = (uint16_t)atoi(argv[2]);
    if (argc > 3) path = argv[3];

    printf("h2c client: connecting to %s:%u, GET %s\n", host, port, path);

    /* ---- shift context ---- */
    shift_t *sh = NULL;
    shift_config_t sh_cfg = {
        .max_entities            = 4096,
        .max_components          = 32,
        .max_collections         = 64,
        .deferred_queue_capacity = 4096,
    };
    if (shift_context_create(&sh_cfg, &sh) != shift_ok) {
        fprintf(stderr, "shift_context_create failed\n");
        return 1;
    }

    /* ---- register sh2 components ---- */
    sh2_component_ids_t comp;
    if (sh2_register_components(sh, &comp) != sh2_ok) {
        fprintf(stderr, "sh2_register_components failed\n");
        shift_context_destroy(sh);
        return 1;
    }

    /* ---- server-path collections (needed even if unused) ---- */
    shift_component_id_t all_comps[] = {
        comp.stream_id, comp.session, comp.req_headers, comp.req_body,
        comp.resp_headers, comp.resp_body, comp.status, comp.io_result,
        comp.domain_tag, comp.peer_cert,
    };
    shift_collection_id_t request_out, response_in, response_out;
    {
        shift_collection_info_t ci = {
            .name = "request_out", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci2 = {
            .name = "response_in", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci3 = {
            .name = "response_out", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_register(sh, &ci, &request_out);
        shift_collection_register(sh, &ci2, &response_in);
        shift_collection_register(sh, &ci3, &response_out);
    }

    /* ---- client-path collections ---- */
    shift_component_id_t connect_comps[] = {
        comp.connect_target, comp.session, comp.io_result,
    };
    shift_collection_id_t connect_in, connect_out, disconnect_in;
    shift_collection_id_t client_request_in, client_cancel_in;
    shift_collection_id_t client_response_out;
    {
        shift_collection_info_t ci_co = {
            .name = "connect_in", .comp_ids = connect_comps,
            .comp_count = sizeof(connect_comps) / sizeof(connect_comps[0]),
        };
        shift_collection_info_t ci_cr = {
            .name = "connect_out", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci_cc = {
            .name = "disconnect_in", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci_ri = {
            .name = "client_request_in", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci_ci = {
            .name = "client_cancel_in", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci_ro = {
            .name = "client_response_out", .comp_ids = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_register(sh, &ci_co, &connect_in);
        shift_collection_register(sh, &ci_cr, &connect_out);
        shift_collection_register(sh, &ci_cc, &disconnect_in);
        shift_collection_register(sh, &ci_ri, &client_request_in);
        shift_collection_register(sh, &ci_ci, &client_cancel_in);
        shift_collection_register(sh, &ci_ro, &client_response_out);
    }

    /* ---- create sh2 context ---- */
    sh2_context_t *ctx = NULL;
    sh2_config_t cfg = {
        .shift               = sh,
        .comp_ids            = comp,
        .max_connections     = MAX_CONNECTIONS,
        .ring_entries        = RING_ENTRIES,
        .buf_count           = BUF_COUNT,
        .buf_size            = BUF_SIZE,
        .request_out         = request_out,
        .response_in         = response_in,
        .response_out      = response_out,
        .enable_connect      = true,
        .client_colls = {
            .connect_in          = connect_in,
            .connect_out         = connect_out,
            .disconnect_in       = disconnect_in,
            .request_in          = client_request_in,
            .cancel_in           = client_cancel_in,
            .response_out        = client_response_out,
        },
    };
    sh2_result_t r = sh2_context_create(&cfg, &ctx);
    if (r != sh2_ok) {
        fprintf(stderr, "sh2_context_create failed: %d (errno=%d: %s)\n",
                r, errno, strerror(errno));
        shift_context_destroy(sh);
        return 1;
    }

    /* ---- initiate connection ---- */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, host, &addr.sin_addr);

    /* create connect entity */
    {
        shift_entity_t ce;
        shift_entity_create_one_begin(sh, connect_in, &ce);

        sh2_connect_target_t *tgt = NULL;
        shift_entity_get_component(sh, ce, comp.connect_target, (void **)&tgt);
        tgt->addr         = addr;
        tgt->hostname     = host;
        tgt->hostname_len = (uint32_t)strlen(host);

        shift_entity_create_one_end(sh, ce);
    }

    /* ---- event loop ---- */
    bool connected      = false;
    bool request_sent   = false;
    bool response_done  = false;

    while (g_running && !response_done) {
        if (sh2_poll(ctx, 0) != sh2_ok)
            break;

        /* check connect_out */
        if (!connected) {
            shift_entity_t *entities = NULL;
            size_t count = 0;
            shift_collection_get_entities(sh, connect_out,
                                          &entities, &count);
            for (size_t i = 0; i < count; i++) {
                sh2_io_result_t *io = NULL;
                shift_entity_get_component(sh, entities[i], comp.io_result,
                                           (void **)&io);
                if (io && io->error == 0) {
                    printf("Connected!\n");
                    connected = true;

                    /* get the session entity for request submission */
                    sh2_session_t *sess = NULL;
                    shift_entity_get_component(sh, entities[i], comp.session,
                                               (void **)&sess);

                    /* submit a GET request */
                    shift_entity_t re;
                    shift_entity_create_one_begin(sh, client_request_in, &re);

                    sh2_session_t *rsess = NULL;
                    shift_entity_get_component(sh, re, comp.session,
                                               (void **)&rsess);
                    rsess->entity = sess->entity;

                    /* build request headers */
                    sh2_req_headers_t *rh = NULL;
                    shift_entity_get_component(sh, re, comp.req_headers,
                                               (void **)&rh);
                    sh2_header_field_t *fields = calloc(4, sizeof(sh2_header_field_t));
                    fields[0] = (sh2_header_field_t){
                        .name = ":method", .name_len = 7,
                        .value = "GET", .value_len = 3,
                    };
                    fields[1] = (sh2_header_field_t){
                        .name = ":path", .name_len = 5,
                        .value = path, .value_len = (uint32_t)strlen(path),
                    };
                    fields[2] = (sh2_header_field_t){
                        .name = ":scheme", .name_len = 7,
                        .value = "http", .value_len = 4,
                    };
                    fields[3] = (sh2_header_field_t){
                        .name = ":authority", .name_len = 10,
                        .value = host, .value_len = (uint32_t)strlen(host),
                    };
                    rh->fields = fields;
                    rh->count  = 4;

                    shift_entity_create_one_end(sh, re);
                    request_sent = true;
                    printf("Sent GET %s\n", path);
                } else {
                    fprintf(stderr, "Connect failed: %d\n",
                            io ? io->error : -1);
                    response_done = true;
                }
                shift_entity_destroy_one(sh, entities[i]);
            }
        }

        /* check client_response_out for completed responses */
        {
            shift_entity_t *entities = NULL;
            size_t count = 0;
            shift_collection_get_entities(sh, client_response_out,
                                          &entities, &count);
            for (size_t i = 0; i < count; i++) {
                sh2_status_t *st = NULL;
                shift_entity_get_component(sh, entities[i], comp.status,
                                           (void **)&st);
                sh2_resp_headers_t *rh = NULL;
                shift_entity_get_component(sh, entities[i], comp.resp_headers,
                                           (void **)&rh);
                sh2_resp_body_t *rb = NULL;
                shift_entity_get_component(sh, entities[i], comp.resp_body,
                                           (void **)&rb);
                sh2_io_result_t *io = NULL;
                shift_entity_get_component(sh, entities[i], comp.io_result,
                                           (void **)&io);

                printf("\n--- Response ---\n");
                printf("Status: %u\n", st ? st->code : 0);
                if (rh) {
                    for (uint32_t j = 0; j < rh->count; j++) {
                        printf("%.*s: %.*s\n",
                               rh->fields[j].name_len, rh->fields[j].name,
                               rh->fields[j].value_len, rh->fields[j].value);
                    }
                }
                if (rb && rb->data && rb->len > 0) {
                    printf("\n%.*s\n", rb->len, (const char *)rb->data);
                }
                printf("io_result: %d\n", io ? io->error : -999);

                shift_entity_destroy_one(sh, entities[i]);
                response_done = true;
            }
        }

        shift_flush(sh);
    }

    /* ---- shutdown ---- */
    sh2_context_destroy(ctx);
    shift_flush(sh);
    shift_context_destroy(sh);
    printf("Done.\n");
    return 0;
}
