#define _GNU_SOURCE

#include <shift_h2.h>
#include <shift.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PORT            9000
#define BACKLOG         4096
#define MAX_CONNECTIONS 16384
#define MAX_STREAMS     (MAX_CONNECTIONS * 128)
#define BUF_COUNT       32768
#define BUF_SIZE        (64 * 1024)
#define RING_ENTRIES    32768

static volatile int g_running = 1;

static void handle_signal(int sig) { (void)sig; g_running = 0; }

typedef struct {
    int worker_id;
    int worker_core;
} worker_config_t;

static void pin_to_core(int core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static char *build_echo_body(const sh2_req_headers_t *rh,
                             const sh2_req_body_t    *rb,
                             uint32_t                *out_len) {
    size_t len = 0;
    for (uint32_t i = 0; i < rh->count; i++)
        len += rh->fields[i].name_len + 2 + rh->fields[i].value_len + 1;
    if (rb->len > 0)
        len += 1 + rb->len;

    char *buf = malloc(len + 1);
    if (!buf) return NULL;

    size_t pos = 0;
    for (uint32_t i = 0; i < rh->count; i++) {
        const sh2_header_field_t *f = &rh->fields[i];
        memcpy(buf + pos, f->name, f->name_len);   pos += f->name_len;
        buf[pos++] = ':'; buf[pos++] = ' ';
        memcpy(buf + pos, f->value, f->value_len); pos += f->value_len;
        buf[pos++] = '\n';
    }
    if (rb->len > 0) {
        buf[pos++] = '\n';
        memcpy(buf + pos, rb->data, rb->len);
        pos += rb->len;
    }

    *out_len = (uint32_t)pos;
    return buf;
}

static void *worker_fn(void *arg) {
    worker_config_t *wcfg = arg;

    pin_to_core(wcfg->worker_core);
    printf("Worker %d: pinned to core %d\n",
           wcfg->worker_id, wcfg->worker_core);

    /* ---- Phase 1: create per-worker shift context ---- */
    shift_t *sh = NULL;
    shift_config_t sh_cfg = {
        .max_entities            = MAX_CONNECTIONS * 16 + MAX_STREAMS + 1024,
        .max_components          = 32,
        .max_collections         = 32,
        .deferred_queue_capacity = MAX_CONNECTIONS * 256,
        .allocator               = {0},
    };
    if (shift_context_create(&sh_cfg, &sh) != shift_ok) {
        fprintf(stderr, "Worker %d: shift_context_create failed\n", wcfg->worker_id);
        return NULL;
    }

    /* ---- Phase 2: register sh2 components ---- */
    sh2_component_ids_t comp;
    if (sh2_register_components(sh, &comp) != sh2_ok) {
        fprintf(stderr, "Worker %d: sh2_register_components failed\n", wcfg->worker_id);
        shift_context_destroy(sh);
        return NULL;
    }

    /* ---- Phase 3: create user-owned result collections ---- */
    shift_component_id_t all_comps[] = {
        comp.stream_id, comp.session, comp.req_headers, comp.req_body,
        comp.resp_headers, comp.resp_body, comp.status, comp.io_result,
        comp.domain_tag, comp.peer_cert,
    };
    shift_collection_id_t request_out;
    shift_collection_id_t response_in, response_result_out;
    {
        shift_collection_info_t ci = {
            .name       = "request_out",
            .comp_ids   = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci2 = {
            .name       = "response_in",
            .comp_ids   = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        shift_collection_info_t ci3 = {
            .name       = "response_result_out",
            .comp_ids   = all_comps,
            .comp_count = sizeof(all_comps) / sizeof(all_comps[0]),
        };
        if (shift_collection_register(sh, &ci, &request_out) != shift_ok ||
            shift_collection_register(sh, &ci2, &response_in) != shift_ok ||
            shift_collection_register(sh, &ci3, &response_result_out) != shift_ok) {
            fprintf(stderr, "Worker %d: failed to register collections\n", wcfg->worker_id);
            shift_context_destroy(sh);
            return NULL;
        }
    }

    /* ---- Phase 4: create sh2 context ---- */
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
    };
    sh2_result_t r = sh2_context_create(&cfg, &ctx);
    if (r != sh2_ok) {
        fprintf(stderr, "Worker %d: sh2_context_create failed: %d (errno=%d: %s)\n",
                wcfg->worker_id, r, errno, strerror(errno));
        shift_context_destroy(sh);
        return NULL;
    }

    if (sh2_listen(ctx, PORT, BACKLOG) != sh2_ok) {
        fprintf(stderr, "Worker %d: sh2_listen failed on port %d\n", wcfg->worker_id, PORT);
        sh2_context_destroy(ctx);
        shift_context_destroy(sh);
        return NULL;
    }

    printf("Worker %d: h2c echo server listening on port %d\n", wcfg->worker_id, PORT);

    /* ---- Event loop ---- */
    while (g_running) {
        if (sh2_poll(ctx, 0) != sh2_ok)
            break;

        /* ---- Consume request_out: build and enqueue echo responses ---- */
        {
            shift_entity_t *entities = NULL;
            size_t          count    = 0;
            shift_collection_get_entities(sh, request_out, &entities, &count);

            for (size_t i = 0; i < count; i++) {
                shift_entity_t e = entities[i];

                sh2_req_headers_t *rqh = NULL;
                sh2_req_body_t    *rqb = NULL;
                shift_entity_get_component(sh, e, comp.req_headers,
                                           (void **)&rqh);
                shift_entity_get_component(sh, e, comp.req_body,
                                           (void **)&rqb);

                uint32_t echo_len = 0;
                char    *echo_buf = build_echo_body(rqh, rqb, &echo_len);

                sh2_header_field_t *resp_fields =
                    malloc(sizeof(sh2_header_field_t));
                if (!resp_fields || !echo_buf) {
                    free(resp_fields);
                    free(echo_buf);
                    shift_entity_destroy_one(sh, e);
                    continue;
                }
                resp_fields[0] = (sh2_header_field_t){
                    .name      = "content-type",
                    .name_len  = 12,
                    .value     = "text/plain",
                    .value_len = 10,
                };

                sh2_resp_headers_t *rh = NULL;
                shift_entity_get_component(sh, e, comp.resp_headers,
                                           (void **)&rh);
                rh->fields = resp_fields;
                rh->count  = 1;

                sh2_resp_body_t *rb = NULL;
                shift_entity_get_component(sh, e, comp.resp_body,
                                           (void **)&rb);
                rb->data = echo_buf;
                rb->len  = echo_len;

                sh2_status_t *st = NULL;
                shift_entity_get_component(sh, e, comp.status,
                                           (void **)&st);
                st->code = 200;

                shift_entity_move_one(sh, e, response_in);
            }
        }

        /* ---- Drain response_result_out ---- */
        {
            shift_entity_t *entities = NULL;
            size_t          count    = 0;
            shift_collection_get_entities(sh, response_result_out,
                                          &entities, &count);

            for (size_t i = 0; i < count; i++) {
                shift_entity_t e = entities[i];

                sh2_io_result_t *io = NULL;
                shift_entity_get_component(sh, e, comp.io_result,
                                           (void **)&io);
                if (io && io->error != 0)
                    fprintf(stderr, "Worker %d: response send failed: %d\n",
                            wcfg->worker_id, io->error);

                shift_entity_destroy_one(sh, e);
            }
        }

        shift_flush(sh);
    }

    /* ---- Shutdown ---- */
    sh2_context_destroy(ctx);
    shift_flush(sh);

    shift_collection_id_t drain_cols[] = {
        request_out, response_in, response_result_out,
    };
    for (int c = 0; c < 3; c++) {
        shift_entity_t *entities = NULL;
        size_t          count    = 0;
        shift_collection_get_entities(sh, drain_cols[c], &entities, &count);
        for (size_t i = 0; i < count; i++)
            shift_entity_destroy_one(sh, entities[i]);
    }
    shift_flush(sh);

    shift_context_destroy(sh);
    printf("Worker %d: shutdown complete\n", wcfg->worker_id);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    int  nworkers = (int)ncpus;
    if (argc > 1)
        nworkers = atoi(argv[1]);
    if (nworkers < 1)
        nworkers = 1;
    if (nworkers > (int)ncpus)
        nworkers = (int)ncpus;

    printf("h2c echo server: %d workers on %ld cores, port %d\n",
           nworkers, ncpus, PORT);

    worker_config_t *configs = calloc((size_t)nworkers, sizeof(worker_config_t));
    pthread_t       *threads = calloc((size_t)nworkers, sizeof(pthread_t));

    for (int i = 0; i < nworkers; i++) {
        configs[i].worker_id   = i;
        configs[i].worker_core = i;
        pthread_create(&threads[i], NULL, worker_fn, &configs[i]);
    }

    for (int i = 0; i < nworkers; i++)
        pthread_join(threads[i], NULL);

    printf("\nShutting down.\n");

    free(threads);
    free(configs);
    return 0;
}
