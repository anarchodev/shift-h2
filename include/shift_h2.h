#pragma once

#include <shift.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

struct io_uring_params;

typedef struct sh2_context sh2_context_t;

/* --------------------------------------------------------------------------
 * Result codes
 * -------------------------------------------------------------------------- */

typedef enum {
    sh2_ok            =  0,
    sh2_error_null    = -1,
    sh2_error_oom     = -2,
    sh2_error_invalid = -3,
    sh2_error_io      = -4,
} sh2_result_t;

/* --------------------------------------------------------------------------
 * Component types
 * -------------------------------------------------------------------------- */

typedef struct {
    uint32_t id;
} sh2_stream_id_t;

/* Entity ID of the internal per-connection session. Use shift_entity_is_stale()
 * to detect connection close without needing a separate close notification. */
typedef struct {
    shift_entity_t entity;
} sh2_session_t;

typedef struct {
    const char *name;
    uint32_t    name_len;
    const char *value;
    uint32_t    value_len;
} sh2_header_field_t;

/* shift-h2 owns req_headers memory; valid until the entity is destroyed.
 * Pseudo-headers (:method, :path, :authority, :scheme) are included. */
typedef struct {
    sh2_header_field_t *fields;
    uint32_t            count;
} sh2_req_headers_t;

/* shift-h2 owns req_body memory; same lifetime as sh2_req_headers_t. */
typedef struct {
    void    *data; /* NULL if request has no body */
    uint32_t len;
} sh2_req_body_t;

/* App allocates resp_headers; shift-h2 frees the fields array via component
 * destructor when the entity is destroyed.  The fields array must be malloc'd.
 * Name/value pointers are NOT freed — they may be literals or borrowed. */
typedef struct {
    sh2_header_field_t *fields;
    uint32_t            count;
} sh2_resp_headers_t;

/* App allocates resp_body; shift-h2 frees data via component destructor
 * when the entity is destroyed.  The data pointer must be malloc'd. */
typedef struct {
    void    *data; /* NULL if response has no body */
    uint32_t len;
} sh2_resp_body_t;

typedef struct {
    uint16_t code; /* e.g. 200, 404 */
} sh2_status_t;

typedef struct {
    int error; /* 0 = success; negative = errno-style error code */
} sh2_io_result_t;

typedef struct {
    uint64_t tag; /* opaque tenant/domain identifier; 0 for h2c */
} sh2_domain_tag_t;

/* Peer certificate information — extracted from the TLS peer certificate
 * after handshake.  All string fields are shift-h2-owned and freed by the
 * component destructor.  When present==false (h2c, or TLS without client
 * cert), all pointers are NULL. */
typedef struct {
    bool     present;                    /* true if peer cert was provided */
    char    *subject_cn;                 /* Common Name from subject, or NULL */
    char    *subject_dn;                 /* full subject distinguished name */
    char    *issuer_dn;                  /* full issuer distinguished name */
    char    *serial_hex;                 /* serial number as hex string */
    uint8_t  fingerprint_sha256[32];     /* SHA-256 of DER-encoded cert */
} sh2_peer_cert_t;

/* Target address + hostname for outgoing HTTP/2 connections */
typedef struct {
    struct sockaddr_in addr;
    const char        *hostname;     /* for TLS SNI + :authority; borrowed, must outlive entity */
    uint32_t           hostname_len;
} sh2_connect_target_t;

/* --------------------------------------------------------------------------
 * Registered IDs
 * -------------------------------------------------------------------------- */

typedef struct {
    shift_component_id_t stream_id;
    shift_component_id_t session;
    shift_component_id_t req_headers;
    shift_component_id_t req_body;
    shift_component_id_t resp_headers;
    shift_component_id_t resp_body;
    shift_component_id_t status;
    shift_component_id_t io_result;
    shift_component_id_t domain_tag;
    shift_component_id_t peer_cert;
    shift_component_id_t connect_target;
} sh2_component_ids_t;

typedef struct {
    /* request_out: full request received (END_STREAM).
     *   Required components: {stream_id, session, req_headers, req_body}.
     *   App moves entities through its own processing collections, then
     *   does a move into response_in once the response is ready. */
    shift_collection_id_t request_out;

    /* response_in: app deposits response-ready entities here.
     *   Required components: {stream_id, session, req_headers, req_body,
     *                         resp_headers, resp_body, status, io_result}.
     *   shift-h2 submits the response to nghttp2, then moves to an internal
     *   sending collection until the stream closes. */
    shift_collection_id_t response_in;

    /* response_result_out: stream fully closed (io_result.error == 0) or
     *   failed (io_result.error < 0).
     *   Required components: same as response_in.
     *   App frees resp_headers/resp_body memory and destroys entity. */
    shift_collection_id_t response_result_out;
} sh2_collection_ids_t;

/* Client (outgoing) collection IDs — only valid when enable_connect is true. */
typedef struct {
    /* connect_out: app creates entities with sh2_connect_target_t here to
     *   initiate an outgoing TCP connection. */
    shift_collection_id_t connect_out;

    /* connect_result_out: connection established (io_result.error == 0) or
     *   failed (io_result.error < 0).  On success, session.entity is set. */
    shift_collection_id_t connect_result_out;

    /* request_in: app deposits request-ready entities here.
     *   Required components: {session, req_headers, req_body}.
     *   req_headers must include :method, :path, :scheme, :authority. */
    shift_collection_id_t request_in;

    /* response_out: completed response entities delivered here.
     *   Components: {stream_id, session, resp_headers, resp_body, status}. */
    shift_collection_id_t response_out;

    /* response_result_out: stream fully closed — app destroys entity.
     *   Components: same as response_out + io_result. */
    shift_collection_id_t response_result_out;
} sh2_client_collection_ids_t;

/* --------------------------------------------------------------------------
 * TLS (optional — requires SH2_HAS_TLS at build time)
 * -------------------------------------------------------------------------- */

#ifdef SH2_HAS_TLS

typedef struct sh2_tls_config sh2_tls_config_t;
typedef uint32_t sh2_cert_id_t;

sh2_result_t sh2_tls_config_create(sh2_tls_config_t **out);
void         sh2_tls_config_destroy(sh2_tls_config_t *cfg);

/* Register a PEM-encoded certificate chain + private key.  Parsed once;
 * OpenSSL types are stored internally.  Returns a cert_id handle. */
sh2_result_t sh2_tls_config_add_cert(sh2_tls_config_t *cfg,
                                      const char *cert_pem,
                                      const char *key_pem,
                                      sh2_cert_id_t *out_id);

/* SNI callback result — returned by the application to select a certificate
 * and associate an opaque domain_tag with the connection. */
typedef struct {
    sh2_cert_id_t cert_id;
    uint64_t      domain_tag;
} sh2_sni_result_t;

/* Called during TLS handshake with the SNI hostname from the client.
 * Return the cert_id of the certificate to use and a domain_tag that
 * will be attached to every request on this connection. */
typedef sh2_sni_result_t (*sh2_sni_callback_t)(
    const char *hostname, uint32_t hostname_len, void *user_data);

sh2_result_t sh2_tls_config_set_sni_callback(sh2_tls_config_t *cfg,
                                              sh2_sni_callback_t cb,
                                              void *user_data);

/* Enable client certificate verification (mutual TLS) on the server.
 * mode: SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, etc.
 * ca_pem: PEM-encoded CA certificate(s) trusted for client certs. */
sh2_result_t sh2_tls_config_set_client_verify(sh2_tls_config_t *cfg,
                                               int verify_mode,
                                               const char *ca_pem);

/* ---------- Client TLS configuration (for outgoing connections) ---------- */

typedef struct sh2_tls_client_config sh2_tls_client_config_t;

sh2_result_t sh2_tls_client_config_create(sh2_tls_client_config_t **out);
void         sh2_tls_client_config_destroy(sh2_tls_client_config_t *cfg);

/* Set client certificate + key for mutual TLS presentation. */
sh2_result_t sh2_tls_client_config_set_cert(sh2_tls_client_config_t *cfg,
                                             const char *cert_pem,
                                             const char *key_pem);

/* Add CA certificate(s) for server verification.
 * If not called, the default OpenSSL trust store is used. */
sh2_result_t sh2_tls_client_config_add_ca(sh2_tls_client_config_t *cfg,
                                           const char *ca_pem);

/* Enable or disable server certificate verification (default: true). */
sh2_result_t sh2_tls_client_config_set_verify(sh2_tls_client_config_t *cfg,
                                               bool verify);

#endif /* SH2_HAS_TLS */

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

typedef struct {
    shift_t             *shift;           /* caller-owned shift context */
    sh2_component_ids_t  comp_ids;        /* from sh2_register_components */
    uint32_t             max_connections; /* maximum concurrent connections */
    uint32_t             ring_entries;    /* io_uring SQ depth */
    uint32_t             buf_count;       /* provided buffer ring size (power of 2) */
    uint32_t             buf_size;        /* recv buffer size per slot */
    /* Optional io_uring params.  When non-NULL the library passes them to
     * shift-io which uses io_uring_queue_init_params(), allowing flags like
     * IORING_SETUP_SQPOLL.  NULL = default (flags 0). */
    struct io_uring_params *ring_params;
    /* User-provided result collections.  Each must carry at least the
     * required sh2 components listed above.  Extra components are allowed
     * and preserved across entity moves. */
    shift_collection_id_t request_out;
    shift_collection_id_t response_in;
    shift_collection_id_t response_result_out;
#ifdef SH2_HAS_TLS
    /* TLS configuration — NULL = cleartext h2c.  Non-NULL enables TLS
     * with ALPN h2 negotiation and SNI-based certificate selection. */
    sh2_tls_config_t *tls;
#endif
    /* Client / outgoing connection support (optional).
     * Set enable_connect = true and provide the five client collections
     * to use sh2_connect() and the client request/response path. */
    bool                        enable_connect;
    sh2_client_collection_ids_t client_colls;
#ifdef SH2_HAS_TLS
    /* Client TLS — NULL = cleartext h2c for outgoing connections. */
    sh2_tls_client_config_t    *tls_client;
#endif
} sh2_config_t;

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

/* Register all sh2 component types on the given shift context.  Call this
 * BEFORE creating user collections so that the returned component IDs can be
 * used in collection registration.  The same IDs must be passed to
 * sh2_context_create via sh2_config_t::comp_ids. */
sh2_result_t sh2_register_components(shift_t *sh, sh2_component_ids_t *out);

sh2_result_t sh2_context_create(const sh2_config_t *cfg, sh2_context_t **out);
void         sh2_context_destroy(sh2_context_t *ctx);
sh2_result_t sh2_listen(sh2_context_t *ctx, uint16_t port, int backlog);
sh2_result_t sh2_poll(sh2_context_t *ctx, uint32_t min_complete);

const sh2_component_ids_t         *sh2_get_component_ids(const sh2_context_t *ctx);
const sh2_collection_ids_t        *sh2_get_collection_ids(const sh2_context_t *ctx);
const sh2_client_collection_ids_t *sh2_get_client_collection_ids(const sh2_context_t *ctx);
