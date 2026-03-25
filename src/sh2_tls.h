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
};

/* Per-connection TLS state */
typedef struct {
    SSL     *ssl;
    BIO     *rbio;          /* raw TCP → SSL_read() */
    BIO     *wbio;          /* SSL_write() → raw TCP */
    uint64_t domain_tag;    /* set during SNI callback */
    bool     handshake_done;
} sh2_tls_conn_t;

/* Context-level TLS init / cleanup */
sh2_result_t sh2_tls_init(sh2_context_t *ctx);
void         sh2_tls_cleanup(sh2_context_t *ctx);

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
