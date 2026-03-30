#ifdef SH2_HAS_TLS

#include "shift_h2_internal.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* --------------------------------------------------------------------------
 * TLS config (user-facing opaque handle)
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_config_create(sh2_tls_config_t **out) {
    if (!out) return sh2_error_null;

    sh2_tls_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return sh2_error_oom;

    *out = cfg;
    return sh2_ok;
}

void sh2_tls_config_destroy(sh2_tls_config_t *cfg) {
    if (!cfg) return;

    for (uint32_t i = 0; i < cfg->cert_count; i++) {
        X509_free(cfg->certs[i].cert);
        EVP_PKEY_free(cfg->certs[i].key);
    }
    free(cfg->certs);
    X509_STORE_free(cfg->client_ca_store);
    free(cfg);
}

sh2_result_t sh2_tls_config_add_cert(sh2_tls_config_t *cfg,
                                      const char *cert_pem,
                                      const char *key_pem,
                                      sh2_cert_id_t *out_id) {
    if (!cfg || !cert_pem || !key_pem || !out_id)
        return sh2_error_null;

    /* parse certificate */
    BIO *cbio = BIO_new_mem_buf(cert_pem, -1);
    if (!cbio) return sh2_error_oom;

    X509 *cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    BIO_free(cbio);
    if (!cert) return sh2_error_invalid;

    /* parse private key */
    BIO *kbio = BIO_new_mem_buf(key_pem, -1);
    if (!kbio) { X509_free(cert); return sh2_error_oom; }

    EVP_PKEY *key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    BIO_free(kbio);
    if (!key) { X509_free(cert); return sh2_error_invalid; }

    /* validate key matches cert */
    if (!X509_check_private_key(cert, key)) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return sh2_error_invalid;
    }

    /* grow certs array */
    if (cfg->cert_count == cfg->cert_cap) {
        uint32_t new_cap = cfg->cert_cap ? cfg->cert_cap * 2 : 4;
        sh2_tls_cert_t *nc = realloc(cfg->certs, new_cap * sizeof(*nc));
        if (!nc) {
            X509_free(cert);
            EVP_PKEY_free(key);
            return sh2_error_oom;
        }
        cfg->certs    = nc;
        cfg->cert_cap = new_cap;
    }

    *out_id = cfg->cert_count;
    cfg->certs[cfg->cert_count++] = (sh2_tls_cert_t){ .cert = cert, .key = key };
    return sh2_ok;
}

sh2_result_t sh2_tls_config_set_sni_callback(sh2_tls_config_t *cfg,
                                              sh2_sni_callback_t cb,
                                              void *user_data) {
    if (!cfg) return sh2_error_null;
    cfg->sni_cb        = cb;
    cfg->sni_user_data = user_data;
    return sh2_ok;
}

/* --------------------------------------------------------------------------
 * ALPN callback — select "h2"
 * -------------------------------------------------------------------------- */

static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                           unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen,
                           void *arg) {
    (void)ssl; (void)arg;

    /* h2 wire format: length-prefixed "h2" */
    static const unsigned char h2_proto[] = { 2, 'h', '2' };

    /* walk client ALPN list */
    const unsigned char *p = in;
    const unsigned char *end = in + inlen;
    while (p < end) {
        unsigned char len = *p++;
        if (p + len > end) break;
        if (len == 2 && p[0] == 'h' && p[1] == '2') {
            *out    = p;
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
        p += len;
    }

    return SSL_TLSEXT_ERR_NOACK;
}

/* --------------------------------------------------------------------------
 * SNI callback — ask application for cert + domain_tag
 * -------------------------------------------------------------------------- */

static int sni_cb(SSL *ssl, int *al, void *arg) {
    (void)al;
    sh2_context_t *ctx = arg;
    sh2_tls_config_t *tcfg = ctx->tls_config;

    const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!hostname || !tcfg->sni_cb)
        return SSL_TLSEXT_ERR_OK; /* use default cert */

    sh2_sni_result_t result = tcfg->sni_cb(
        hostname, (uint32_t)strlen(hostname), tcfg->sni_user_data);

    if (result.cert_id < tcfg->cert_count) {
        SSL_use_certificate(ssl, tcfg->certs[result.cert_id].cert);
        SSL_use_PrivateKey(ssl, tcfg->certs[result.cert_id].key);
    }

    /* store domain_tag on the per-connection TLS state */
    sh2_tls_conn_t *tconn = SSL_get_app_data(ssl);
    if (tconn)
        tconn->domain_tag = result.domain_tag;

    return SSL_TLSEXT_ERR_OK;
}

/* --------------------------------------------------------------------------
 * Context-level TLS init / cleanup
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_init(sh2_context_t *ctx) {
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) return sh2_error_oom;

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_RENEGOTIATION);

    /* ALPN */
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, ctx);

    /* SNI */
    SSL_CTX_set_tlsext_servername_callback(ssl_ctx, sni_cb);
    SSL_CTX_set_tlsext_servername_arg(ssl_ctx, ctx);

    /* set default cert (first registered) */
    sh2_tls_config_t *tcfg = ctx->tls_config;
    if (tcfg->cert_count > 0) {
        SSL_CTX_use_certificate(ssl_ctx, tcfg->certs[0].cert);
        SSL_CTX_use_PrivateKey(ssl_ctx, tcfg->certs[0].key);
    }

    /* mTLS: client certificate verification */
    if (tcfg->client_verify_mode != 0 && tcfg->client_ca_store) {
        SSL_CTX_set_verify(ssl_ctx, tcfg->client_verify_mode, NULL);
        SSL_CTX_set1_verify_cert_store(ssl_ctx, tcfg->client_ca_store);
    }

    ctx->ssl_ctx = ssl_ctx;
    return sh2_ok;
}

void sh2_tls_cleanup(sh2_context_t *ctx) {
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
}

/* --------------------------------------------------------------------------
 * Per-connection TLS lifecycle
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_conn_create(sh2_context_t *ctx, uint32_t conn_idx) {
    sh2_tls_conn_t *tconn = calloc(1, sizeof(*tconn));
    if (!tconn) return sh2_error_oom;

    tconn->ssl = SSL_new(ctx->ssl_ctx);
    if (!tconn->ssl) { free(tconn); return sh2_error_oom; }

    tconn->rbio = BIO_new(BIO_s_mem());
    tconn->wbio = BIO_new(BIO_s_mem());
    if (!tconn->rbio || !tconn->wbio) {
        /* SSL_free won't free BIOs not yet set */
        BIO_free(tconn->rbio);
        BIO_free(tconn->wbio);
        SSL_free(tconn->ssl);
        free(tconn);
        return sh2_error_oom;
    }

    SSL_set_bio(tconn->ssl, tconn->rbio, tconn->wbio); /* SSL owns BIOs now */
    SSL_set_accept_state(tconn->ssl);
    SSL_set_app_data(tconn->ssl, tconn);

    ctx->conns[conn_idx].tls = tconn;
    return sh2_ok;
}

static void free_peer_cert(sh2_peer_cert_t *pc);

void sh2_tls_conn_destroy(sh2_context_t *ctx, uint32_t conn_idx) {
    sh2_tls_conn_t *tconn = ctx->conns[conn_idx].tls;
    if (!tconn) return;
    free_peer_cert(&tconn->peer_cert);
    SSL_free(tconn->ssl); /* also frees rbio and wbio */
    free(tconn);
    ctx->conns[conn_idx].tls = NULL;
}

/* --------------------------------------------------------------------------
 * Extract peer certificate info after handshake
 * -------------------------------------------------------------------------- */

static char *x509_name_oneline(X509_NAME *name) {
    if (!name) return NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    char *result = NULL;
    if (len > 0 && data) {
        result = malloc((size_t)len + 1);
        if (result) { memcpy(result, data, (size_t)len); result[len] = '\0'; }
    }
    BIO_free(bio);
    return result;
}

static char *x509_get_cn(X509 *cert) {
    X509_NAME *subj = X509_get_subject_name(cert);
    if (!subj) return NULL;
    int idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (idx < 0) return NULL;
    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subj, idx);
    if (!entry) return NULL;
    ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(entry);
    if (!asn1) return NULL;
    const unsigned char *utf8 = NULL;
    int len = ASN1_STRING_to_UTF8((unsigned char **)&utf8, asn1);
    if (len < 0) return NULL;
    char *result = malloc((size_t)len + 1);
    if (result) { memcpy(result, utf8, (size_t)len); result[len] = '\0'; }
    OPENSSL_free((void *)utf8);
    return result;
}

static char *asn1_integer_to_hex(const ASN1_INTEGER *ai) {
    BIGNUM *bn = ASN1_INTEGER_to_BN(ai, NULL);
    if (!bn) return NULL;
    char *hex = BN_bn2hex(bn);
    BN_free(bn);
    if (!hex) return NULL;
    char *result = strdup(hex);
    OPENSSL_free(hex);
    return result;
}

static void extract_peer_cert(sh2_tls_conn_t *tconn) {
    X509 *cert = SSL_get0_peer_certificate(tconn->ssl);
    if (!cert) {
        tconn->peer_cert.present = false;
        return;
    }

    tconn->peer_cert.present    = true;
    tconn->peer_cert.subject_cn = x509_get_cn(cert);
    tconn->peer_cert.subject_dn = x509_name_oneline(X509_get_subject_name(cert));
    tconn->peer_cert.issuer_dn  = x509_name_oneline(X509_get_issuer_name(cert));
    tconn->peer_cert.serial_hex = asn1_integer_to_hex(X509_get0_serialNumber(cert));

    /* SHA-256 fingerprint of DER-encoded cert */
    unsigned int fprint_len = 0;
    X509_digest(cert, EVP_sha256(), tconn->peer_cert.fingerprint_sha256, &fprint_len);
}

static void free_peer_cert(sh2_peer_cert_t *pc) {
    free(pc->subject_cn);
    free(pc->subject_dn);
    free(pc->issuer_dn);
    free(pc->serial_hex);
    *pc = (sh2_peer_cert_t){0};
}

/* --------------------------------------------------------------------------
 * Feed raw TCP data — handshake or decrypt
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_feed(sh2_context_t *ctx, uint32_t conn_idx,
                           const uint8_t *raw, uint32_t raw_len,
                           uint8_t *decrypt_buf, uint32_t decrypt_buf_cap,
                           uint32_t *out_len) {
    (void)ctx;
    sh2_tls_conn_t *tconn = ctx->conns[conn_idx].tls;
    *out_len = 0;

    /* push raw TCP bytes into the read BIO */
    if (raw_len > 0) {
        int written = BIO_write(tconn->rbio, raw, (int)raw_len);
        if (written <= 0)
            return sh2_error_io;
    }

    /* drive handshake if not complete */
    if (!tconn->handshake_done) {
        int ret = SSL_do_handshake(tconn->ssl);
        if (ret == 1) {
            tconn->handshake_done = true;
            extract_peer_cert(tconn);
            /* fall through to SSL_read for any buffered app data */
        } else {
            int err = SSL_get_error(tconn->ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                return sh2_ok; /* need more TCP data */
            return sh2_error_io;
        }
    }

    /* decrypt application data */
    uint32_t total = 0;
    for (;;) {
        if (total >= decrypt_buf_cap)
            break;
        int n = SSL_read(tconn->ssl, decrypt_buf + total,
                         (int)(decrypt_buf_cap - total));
        if (n > 0) {
            total += (uint32_t)n;
            continue;
        }
        int err = SSL_get_error(tconn->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_ZERO_RETURN)
            break;
        return sh2_error_io;
    }
    *out_len = total;
    return sh2_ok;
}

/* --------------------------------------------------------------------------
 * Encrypt plaintext → ciphertext
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_encrypt(sh2_context_t *ctx, uint32_t conn_idx,
                              const uint8_t *plain, uint32_t plain_len,
                              uint8_t **out_buf, uint32_t *out_len) {
    (void)ctx;
    sh2_tls_conn_t *tconn = ctx->conns[conn_idx].tls;
    *out_buf = NULL;
    *out_len = 0;

    int ret = SSL_write(tconn->ssl, plain, (int)plain_len);
    if (ret <= 0)
        return sh2_error_io;

    /* drain wbio → ciphertext */
    int pending = (int)BIO_ctrl_pending(tconn->wbio);
    if (pending <= 0)
        return sh2_ok;

    uint8_t *buf = malloc((size_t)pending);
    if (!buf) return sh2_error_oom;

    int n = BIO_read(tconn->wbio, buf, pending);
    if (n <= 0) { free(buf); return sh2_error_io; }

    *out_buf = buf;
    *out_len = (uint32_t)n;
    return sh2_ok;
}

/* --------------------------------------------------------------------------
 * Drain wbio (handshake data, alerts)
 * -------------------------------------------------------------------------- */

uint8_t *sh2_tls_drain_wbio(sh2_context_t *ctx, uint32_t conn_idx,
                             uint32_t *out_len) {
    sh2_tls_conn_t *tconn = ctx->conns[conn_idx].tls;
    *out_len = 0;

    int pending = (int)BIO_ctrl_pending(tconn->wbio);
    if (pending <= 0)
        return NULL;

    uint8_t *buf = malloc((size_t)pending);
    if (!buf) return NULL;

    int n = BIO_read(tconn->wbio, buf, pending);
    if (n <= 0) { free(buf); return NULL; }

    *out_len = (uint32_t)n;
    return buf;
}

/* --------------------------------------------------------------------------
 * Client TLS config API
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_client_config_create(sh2_tls_client_config_t **out) {
    if (!out) return sh2_error_null;
    sh2_tls_client_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return sh2_error_oom;
    cfg->verify_server = true;
    *out = cfg;
    return sh2_ok;
}

void sh2_tls_client_config_destroy(sh2_tls_client_config_t *cfg) {
    if (!cfg) return;
    X509_free(cfg->client_cert);
    EVP_PKEY_free(cfg->client_key);
    X509_STORE_free(cfg->ca_store);
    free(cfg);
}

sh2_result_t sh2_tls_client_config_set_cert(sh2_tls_client_config_t *cfg,
                                             const char *cert_pem,
                                             const char *key_pem) {
    if (!cfg || !cert_pem || !key_pem) return sh2_error_null;

    BIO *cbio = BIO_new_mem_buf(cert_pem, -1);
    if (!cbio) return sh2_error_oom;
    X509 *cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    BIO_free(cbio);
    if (!cert) return sh2_error_invalid;

    BIO *kbio = BIO_new_mem_buf(key_pem, -1);
    if (!kbio) { X509_free(cert); return sh2_error_oom; }
    EVP_PKEY *key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    BIO_free(kbio);
    if (!key) { X509_free(cert); return sh2_error_invalid; }

    if (!X509_check_private_key(cert, key)) {
        X509_free(cert); EVP_PKEY_free(key);
        return sh2_error_invalid;
    }

    X509_free(cfg->client_cert);
    EVP_PKEY_free(cfg->client_key);
    cfg->client_cert = cert;
    cfg->client_key  = key;
    return sh2_ok;
}

sh2_result_t sh2_tls_client_config_add_ca(sh2_tls_client_config_t *cfg,
                                           const char *ca_pem) {
    if (!cfg || !ca_pem) return sh2_error_null;

    if (!cfg->ca_store) {
        cfg->ca_store = X509_STORE_new();
        if (!cfg->ca_store) return sh2_error_oom;
    }

    BIO *bio = BIO_new_mem_buf(ca_pem, -1);
    if (!bio) return sh2_error_oom;

    X509 *ca = NULL;
    int added = 0;
    while ((ca = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        X509_STORE_add_cert(cfg->ca_store, ca);
        X509_free(ca);
        added++;
    }
    BIO_free(bio);
    return added > 0 ? sh2_ok : sh2_error_invalid;
}

sh2_result_t sh2_tls_client_config_set_verify(sh2_tls_client_config_t *cfg,
                                               bool verify) {
    if (!cfg) return sh2_error_null;
    cfg->verify_server = verify;
    return sh2_ok;
}

/* --------------------------------------------------------------------------
 * Client TLS context init / cleanup
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_client_init(sh2_context_t *ctx) {
    sh2_tls_client_config_t *tcfg = ctx->tls_client_config;
    if (!tcfg) return sh2_error_null;

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) return sh2_error_oom;

    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);

    /* ALPN: advertise h2 */
    static const unsigned char alpn[] = { 2, 'h', '2' };
    SSL_CTX_set_alpn_protos(ssl_ctx, alpn, sizeof(alpn));

    /* client certificate (for mTLS) */
    if (tcfg->client_cert) {
        SSL_CTX_use_certificate(ssl_ctx, tcfg->client_cert);
        SSL_CTX_use_PrivateKey(ssl_ctx, tcfg->client_key);
    }

    /* CA trust store */
    if (tcfg->ca_store) {
        SSL_CTX_set1_verify_cert_store(ssl_ctx, tcfg->ca_store);
    } else {
        SSL_CTX_set_default_verify_paths(ssl_ctx);
    }

    /* server verification */
    if (tcfg->verify_server) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

    ctx->ssl_client_ctx = ssl_ctx;
    return sh2_ok;
}

void sh2_tls_client_cleanup(sh2_context_t *ctx) {
    if (ctx->ssl_client_ctx) {
        SSL_CTX_free(ctx->ssl_client_ctx);
        ctx->ssl_client_ctx = NULL;
    }
}

sh2_result_t sh2_tls_client_conn_create(sh2_context_t *ctx, uint32_t conn_idx,
                                         const char *hostname) {
    sh2_tls_conn_t *tconn = calloc(1, sizeof(*tconn));
    if (!tconn) return sh2_error_oom;

    tconn->ssl = SSL_new(ctx->ssl_client_ctx);
    if (!tconn->ssl) { free(tconn); return sh2_error_oom; }

    tconn->rbio = BIO_new(BIO_s_mem());
    tconn->wbio = BIO_new(BIO_s_mem());
    if (!tconn->rbio || !tconn->wbio) {
        BIO_free(tconn->rbio);
        BIO_free(tconn->wbio);
        SSL_free(tconn->ssl);
        free(tconn);
        return sh2_error_oom;
    }

    SSL_set_bio(tconn->ssl, tconn->rbio, tconn->wbio);
    SSL_set_connect_state(tconn->ssl);
    SSL_set_app_data(tconn->ssl, tconn);

    /* SNI hostname */
    if (hostname)
        SSL_set_tlsext_host_name(tconn->ssl, hostname);

    /* hostname verification */
    if (hostname && ctx->tls_client_config->verify_server)
        SSL_set1_host(tconn->ssl, hostname);

    ctx->conns[conn_idx].tls = tconn;
    return sh2_ok;
}

/* --------------------------------------------------------------------------
 * Server mTLS: client certificate verification
 * -------------------------------------------------------------------------- */

sh2_result_t sh2_tls_config_set_client_verify(sh2_tls_config_t *cfg,
                                               int verify_mode,
                                               const char *ca_pem) {
    if (!cfg || !ca_pem) return sh2_error_null;

    X509_STORE *store = X509_STORE_new();
    if (!store) return sh2_error_oom;

    BIO *bio = BIO_new_mem_buf(ca_pem, -1);
    if (!bio) { X509_STORE_free(store); return sh2_error_oom; }

    X509 *ca = NULL;
    int added = 0;
    while ((ca = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        X509_STORE_add_cert(store, ca);
        X509_free(ca);
        added++;
    }
    BIO_free(bio);

    if (added == 0) {
        X509_STORE_free(store);
        return sh2_error_invalid;
    }

    X509_STORE_free(cfg->client_ca_store);
    cfg->client_verify_mode = verify_mode;
    cfg->client_ca_store    = store;
    return sh2_ok;
}

#endif /* SH2_HAS_TLS */
