#pragma once

#ifdef SH2_HAS_TLS

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdbool.h>
#include <stdint.h>

/* shift_h2.h is already included by shift_h2_internal.h before this header */
typedef struct sh2_context sh2_context_t;

/* Per-certificate storage (parsed once at registration time) */
typedef struct {
    X509     *cert;
    EVP_PKEY *key;
} sh2_tls_cert_t;

/* Opaque TLS config — user-facing handle wraps internal storage */
struct sh2_tls_config {
    sh2_tls_cert_t     *certs;
    uint32_t            cert_count;
    uint32_t            cert_cap;
    sh2_sni_callback_t  sni_cb;
    void               *sni_user_data;
    /* mTLS: client certificate verification */
    int                 client_verify_mode;
    X509_STORE         *client_ca_store;
};

/* Client-side TLS config (for outgoing connections) */
struct sh2_tls_client_config {
    X509       *client_cert;    /* NULL if no mTLS */
    EVP_PKEY   *client_key;
    X509_STORE *ca_store;       /* NULL = default trust store */
    bool        verify_server;  /* default true */
};

/* Per-connection TLS state */
typedef struct {
    SSL     *ssl;
    BIO     *rbio;          /* raw TCP → SSL_read() */
    BIO     *wbio;          /* SSL_write() → raw TCP */
    uint64_t domain_tag;    /* set during SNI callback */
    bool     handshake_done;
    /* peer certificate info — extracted once at handshake completion */
    sh2_peer_cert_t peer_cert;
} sh2_tls_conn_t;

/* Context-level TLS init / cleanup (server) */
sh2_result_t sh2_tls_init(sh2_context_t *ctx);
void         sh2_tls_cleanup(sh2_context_t *ctx);

/* Context-level TLS init / cleanup (client) */
sh2_result_t sh2_tls_client_init(sh2_context_t *ctx);
void         sh2_tls_client_cleanup(sh2_context_t *ctx);

/* Per-connection client TLS lifecycle */
sh2_result_t sh2_tls_client_conn_create(sh2_context_t *ctx, uint32_t conn_idx,
                                         const char *hostname);

/* Per-connection lifecycle */
sh2_result_t sh2_tls_conn_create(sh2_context_t *ctx, uint32_t conn_idx);
void         sh2_tls_conn_destroy(sh2_context_t *ctx, uint32_t conn_idx);

/* Feed raw TCP bytes, drive handshake or decrypt.
 * On success: *out_len bytes of decrypted plaintext written to decrypt_buf.
 *   out_len==0 with handshake_done==false means handshake needs more data.
 * Returns sh2_error_io on fatal SSL error. */
sh2_result_t sh2_tls_feed(sh2_context_t *ctx, uint32_t conn_idx,
                           const uint8_t *raw, uint32_t raw_len,
                           uint8_t *decrypt_buf, uint32_t decrypt_buf_cap,
                           uint32_t *out_len);

/* Encrypt plaintext via SSL_write, return ciphertext from wbio.
 * Caller owns *out_buf (malloc'd). */
sh2_result_t sh2_tls_encrypt(sh2_context_t *ctx, uint32_t conn_idx,
                              const uint8_t *plain, uint32_t plain_len,
                              uint8_t **out_buf, uint32_t *out_len);

/* Drain pending data from wbio (handshake responses, alerts).
 * Returns malloc'd buffer or NULL if nothing pending. */
uint8_t *sh2_tls_drain_wbio(sh2_context_t *ctx, uint32_t conn_idx,
                             uint32_t *out_len);

#endif /* SH2_HAS_TLS */
