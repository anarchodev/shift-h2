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

static char *load_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <host> <port> [path] [--cert cert.pem --key key.pem] "
        "[--ca ca.pem] [--no-verify]\n", prog);
}

int main(int argc, char **argv) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    if (argc < 3) { usage(argv[0]); return 1; }

    const char *host      = argv[1];
    uint16_t    port      = (uint16_t)atoi(argv[2]);
    const char *path      = argc > 3 && argv[3][0] != '-' ? argv[3] : "/";
    const char *cert_path = NULL;
    const char *key_path  = NULL;
    const char *ca_path   = NULL;
    bool        verify    = true;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc)
            cert_path = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key_path = argv[++i];
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc)
            ca_path = argv[++i];
        else if (strcmp(argv[i], "--no-verify") == 0)
            verify = false;
    }

    printf("h2 TLS client: connecting to %s:%u, GET %s\n", host, port, path);

    /* ---- client TLS config ---- */
    sh2_tls_client_config_t *tls_client = NULL;
    sh2_tls_client_config_create(&tls_client);

    if (cert_path && key_path) {
        char *cert_pem = load_file(cert_path);
        char *key_pem  = load_file(key_path);
        if (cert_pem && key_pem)
            sh2_tls_client_config_set_cert(tls_client, cert_pem, key_pem);
        free(cert_pem);
        free(key_pem);
        printf("Client certificate loaded for mTLS\n");
    }

    if (ca_path) {
        char *ca_pem = load_file(ca_path);
        if (ca_pem)
            sh2_tls_client_config_add_ca(tls_client, ca_pem);
        free(ca_pem);
    }

    sh2_tls_client_config_set_verify(tls_client, verify);
    if (!verify)
        printf("WARNING: server certificate verification disabled\n");

    /* ---- shift context ---- */
    shift_t *sh = NULL;
    shift_config_t sh_cfg = {
        .max_entities            = 4096,
        .max_components          = 32,
        .max_collections         = 64,
        .deferred_queue_capacity = 4096,
    };
    shift_context_create(&sh_cfg, &sh);

    sh2_component_ids_t comp;
    sh2_register_components(sh, &comp);

    shift_component_id_t all_comps[] = {
        comp.stream_id, comp.session, comp.req_headers, comp.req_body,
        comp.resp_headers, comp.resp_body, comp.status, comp.io_result,
        comp.domain_tag, comp.peer_cert,
    };

    shift_component_id_t connect_in_comps[] = {
        comp.connect_target, comp.session, comp.io_result,
    };
    shift_component_id_t connect_out_comps[] = {
        comp.connect_target, comp.session,
    };
    shift_component_id_t connect_err_comps[] = {
        comp.connect_target, comp.io_result,
    };
    shift_collection_id_t connect_in, connect_out, connect_errors, disconnect_in;
    shift_collection_id_t client_request_in, client_cancel_in;
    shift_collection_id_t client_response_out;
    {
        shift_collection_info_t ci_co = { .name = "connect_in", .comp_ids = connect_in_comps,
                                          .comp_count = sizeof(connect_in_comps)/sizeof(connect_in_comps[0]) };
        shift_collection_info_t ci_cr = { .name = "connect_out", .comp_ids = connect_out_comps,
                                          .comp_count = sizeof(connect_out_comps)/sizeof(connect_out_comps[0]) };
        shift_collection_info_t ci_ce = { .name = "connect_errors", .comp_ids = connect_err_comps,
                                          .comp_count = sizeof(connect_err_comps)/sizeof(connect_err_comps[0]) };
        shift_collection_info_t ci_cc = { .name = "disconnect_in", .comp_ids = all_comps,
                                          .comp_count = sizeof(all_comps)/sizeof(all_comps[0]) };
        shift_collection_info_t ci_ri = { .name = "client_request_in", .comp_ids = all_comps,
                                          .comp_count = sizeof(all_comps)/sizeof(all_comps[0]) };
        shift_collection_info_t ci_ci = { .name = "client_cancel_in", .comp_ids = all_comps,
                                          .comp_count = sizeof(all_comps)/sizeof(all_comps[0]) };
        shift_collection_info_t ci_ro = { .name = "client_response_out", .comp_ids = all_comps,
                                          .comp_count = sizeof(all_comps)/sizeof(all_comps[0]) };
        shift_collection_register(sh, &ci_co, &connect_in);
        shift_collection_register(sh, &ci_cr, &connect_out);
        shift_collection_register(sh, &ci_ce, &connect_errors);
        shift_collection_register(sh, &ci_cc, &disconnect_in);
        shift_collection_register(sh, &ci_ri, &client_request_in);
        shift_collection_register(sh, &ci_ci, &client_cancel_in);
        shift_collection_register(sh, &ci_ro, &client_response_out);
    }

    sh2_context_t *ctx = NULL;
    sh2_config_t cfg = {
        .shift               = sh,
        .comp_ids            = comp,
        .max_connections     = MAX_CONNECTIONS,
        .ring_entries        = RING_ENTRIES,
        .buf_count           = BUF_COUNT,
        .buf_size            = BUF_SIZE,
        .client_only         = true,
        .enable_connect      = true,
        .client_colls = {
            .connect_in          = connect_in,
            .connect_out         = connect_out,
            .connect_errors      = connect_errors,
            .disconnect_in       = disconnect_in,
            .request_in          = client_request_in,
            .cancel_in           = client_cancel_in,
            .response_out        = client_response_out,
        },
        .tls_client          = tls_client,
    };
    sh2_result_t r = sh2_context_create(&cfg, &ctx);
    if (r != sh2_ok) {
        fprintf(stderr, "sh2_context_create failed: %d (errno=%d: %s)\n",
                r, errno, strerror(errno));
        sh2_tls_client_config_destroy(tls_client);
        shift_context_destroy(sh);
        return 1;
    }

    /* ---- initiate connection ---- */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, host, &addr.sin_addr);

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
    bool connected     = false;
    bool request_sent  = false;
    bool response_done = false;

    while (g_running && !response_done) {
        if (sh2_poll(ctx, 0) != sh2_ok)
            break;

        if (!connected) {
            shift_entity_t *entities = NULL;
            size_t count = 0;
            shift_collection_get_entities(sh, connect_out,
                                          &entities, &count);
            for (size_t i = 0; i < count; i++) {
                printf("TLS connection established!\n");
                connected = true;

                sh2_session_t *sess = NULL;
                shift_entity_get_component(sh, entities[i], comp.session,
                                           (void **)&sess);

                shift_entity_t re;
                shift_entity_create_one_begin(sh, client_request_in, &re);

                sh2_session_t *rsess = NULL;
                shift_entity_get_component(sh, re, comp.session,
                                           (void **)&rsess);
                rsess->entity = sess->entity;

                sh2_req_headers_t *rh = NULL;
                shift_entity_get_component(sh, re, comp.req_headers,
                                           (void **)&rh);
                sh2_header_field_t *fields = calloc(4, sizeof(sh2_header_field_t));
                fields[0] = (sh2_header_field_t){ ":method",    7, "GET", 3 };
                fields[1] = (sh2_header_field_t){ ":path",      5, path, (uint32_t)strlen(path) };
                fields[2] = (sh2_header_field_t){ ":scheme",    7, "https", 5 };
                fields[3] = (sh2_header_field_t){ ":authority", 10, host, (uint32_t)strlen(host) };
                rh->fields = fields;
                rh->count  = 4;

                shift_entity_create_one_end(sh, re);
                request_sent = true;
                printf("Sent GET %s\n", path);
                shift_entity_destroy_one(sh, entities[i]);
            }

            /* check connect_errors */
            shift_collection_get_entities(sh, connect_errors,
                                          &entities, &count);
            for (size_t i = 0; i < count; i++) {
                sh2_io_result_t *io = NULL;
                shift_entity_get_component(sh, entities[i], comp.io_result,
                                           (void **)&io);
                fprintf(stderr, "Connect failed: %d\n", io ? io->error : -1);
                shift_entity_destroy_one(sh, entities[i]);
                response_done = true;
            }
        }

        /* drain client_response_out */
        {
            shift_entity_t *entities = NULL;
            size_t count = 0;
            shift_collection_get_entities(sh, client_response_out,
                                          &entities, &count);
            for (size_t i = 0; i < count; i++) {
                sh2_status_t *st = NULL;
                shift_entity_get_component(sh, entities[i], comp.status, (void **)&st);
                sh2_resp_body_t *rb = NULL;
                shift_entity_get_component(sh, entities[i], comp.resp_body, (void **)&rb);
                sh2_io_result_t *io = NULL;
                shift_entity_get_component(sh, entities[i], comp.io_result, (void **)&io);

                printf("\n--- Response (status=%u, io=%d) ---\n",
                       st ? st->code : 0, io ? io->error : -999);
                if (rb && rb->data && rb->len > 0)
                    printf("%.*s\n", rb->len, (const char *)rb->data);

                shift_entity_destroy_one(sh, entities[i]);
                response_done = true;
            }
        }

        shift_flush(sh);
    }

    sh2_context_destroy(ctx);
    shift_flush(sh);
    shift_context_destroy(sh);
    sh2_tls_client_config_destroy(tls_client);
    printf("Done.\n");
    return 0;
}
