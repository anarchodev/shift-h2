#define _GNU_SOURCE

#include <shift_h2.h>
#include <shift.h>

#include <errno.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT            9443
#define BACKLOG         4096
#define MAX_CONNECTIONS 1024
#define BUF_COUNT       4096
#define BUF_SIZE        (64 * 1024)
#define RING_ENTRIES    4096

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
        "Usage: %s <server-cert.pem> <server-key.pem> <client-ca.pem>\n"
        "\n"
        "Starts an h2 echo server with mutual TLS.\n"
        "  server-cert.pem  Server certificate\n"
        "  server-key.pem   Server private key\n"
        "  client-ca.pem    CA certificate(s) trusted for client certs\n",
        prog);
}

int main(int argc, char **argv) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    if (argc < 4) { usage(argv[0]); return 1; }

    char *cert_pem     = load_file(argv[1]);
    char *key_pem      = load_file(argv[2]);
    char *client_ca_pem = load_file(argv[3]);
    if (!cert_pem || !key_pem || !client_ca_pem) {
        fprintf(stderr, "Failed to load PEM files\n");
        free(cert_pem); free(key_pem); free(client_ca_pem);
        return 1;
    }

    /* ---- TLS config with mTLS ---- */
    sh2_tls_config_t *tls = NULL;
    sh2_tls_config_create(&tls);

    sh2_cert_id_t cert_id;
    if (sh2_tls_config_add_cert(tls, cert_pem, key_pem, &cert_id) != sh2_ok) {
        fprintf(stderr, "sh2_tls_config_add_cert failed\n");
        return 1;
    }
    free(cert_pem);
    free(key_pem);

    /* require client certificate */
    if (sh2_tls_config_set_client_verify(tls,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            client_ca_pem) != sh2_ok) {
        fprintf(stderr, "sh2_tls_config_set_client_verify failed\n");
        return 1;
    }
    free(client_ca_pem);
    printf("mTLS enabled: client certificates required\n");

    /* ---- shift + sh2 setup ---- */
    shift_t *sh = NULL;
    shift_config_t sh_cfg = {
        .max_entities            = MAX_CONNECTIONS * 16 + 4096,
        .max_components          = 32,
        .max_collections         = 32,
        .deferred_queue_capacity = MAX_CONNECTIONS * 64,
    };
    shift_context_create(&sh_cfg, &sh);

    sh2_component_ids_t comp;
    sh2_register_components(sh, &comp);

    shift_component_id_t all_comps[] = {
        comp.stream_id, comp.session, comp.req_headers, comp.req_body,
        comp.resp_headers, comp.resp_body, comp.status, comp.io_result,
        comp.domain_tag,
    };
    shift_collection_id_t request_out, response_in, response_result_out;
    {
        shift_collection_info_t ci  = { .name = "request_out",         .comp_ids = all_comps,
                                        .comp_count = sizeof(all_comps)/sizeof(all_comps[0]) };
        shift_collection_info_t ci2 = { .name = "response_in",         .comp_ids = all_comps,
                                        .comp_count = sizeof(all_comps)/sizeof(all_comps[0]) };
        shift_collection_info_t ci3 = { .name = "response_result_out", .comp_ids = all_comps,
                                        .comp_count = sizeof(all_comps)/sizeof(all_comps[0]) };
        shift_collection_register(sh, &ci, &request_out);
        shift_collection_register(sh, &ci2, &response_in);
        shift_collection_register(sh, &ci3, &response_result_out);
    }

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
        .response_result_out = response_result_out,
        .tls                 = tls,
    };
    sh2_result_t r = sh2_context_create(&cfg, &ctx);
    if (r != sh2_ok) {
        fprintf(stderr, "sh2_context_create failed: %d\n", r);
        return 1;
    }

    if (sh2_listen(ctx, PORT, BACKLOG) != sh2_ok) {
        fprintf(stderr, "sh2_listen failed on port %d\n", PORT);
        return 1;
    }

    printf("h2 mTLS echo server listening on port %d\n", PORT);

    /* ---- event loop ---- */
    while (g_running) {
        if (sh2_poll(ctx, 0) != sh2_ok)
            break;

        /* echo requests back */
        {
            shift_entity_t *entities = NULL;
            size_t count = 0;
            shift_collection_get_entities(sh, request_out, &entities, &count);

            for (size_t i = 0; i < count; i++) {
                shift_entity_t e = entities[i];

                sh2_header_field_t *resp_fields =
                    malloc(sizeof(sh2_header_field_t));
                resp_fields[0] = (sh2_header_field_t){
                    .name = "content-type", .name_len = 12,
                    .value = "text/plain",  .value_len = 10,
                };

                sh2_resp_headers_t *rh = NULL;
                shift_entity_get_component(sh, e, comp.resp_headers, (void **)&rh);
                rh->fields = resp_fields;
                rh->count  = 1;

                sh2_resp_body_t *rb = NULL;
                shift_entity_get_component(sh, e, comp.resp_body, (void **)&rb);
                rb->data = strdup("mTLS echo OK\n");
                rb->len  = 13;

                sh2_status_t *st = NULL;
                shift_entity_get_component(sh, e, comp.status, (void **)&st);
                st->code = 200;

                shift_entity_move_one(sh, e, response_in);
            }
        }

        /* drain results */
        {
            shift_entity_t *entities = NULL;
            size_t count = 0;
            shift_collection_get_entities(sh, response_result_out, &entities, &count);
            for (size_t i = 0; i < count; i++)
                shift_entity_destroy_one(sh, entities[i]);
        }

        shift_flush(sh);
    }

    sh2_context_destroy(ctx);
    shift_flush(sh);
    shift_context_destroy(sh);
    sh2_tls_config_destroy(tls);
    printf("\nShutdown complete.\n");
    return 0;
}
