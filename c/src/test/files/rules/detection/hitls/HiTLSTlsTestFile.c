/* Test file for HiTLS TLS/DTLS detection rules. */

#include <stdlib.h>

void test_tls_config(void) {
    /* TLS configuration */
    void *cfg = HITLS_CFG_NewTlsConfig();
    if (cfg) HITLS_CFG_FreeConfig(cfg);
}

void test_dtls_config(void) {
    /* DTLS configuration */
    void *cfg = HITLS_CFG_NewDtlsConfig();
    if (cfg) HITLS_CFG_FreeConfig(cfg);
}

void test_hitls_new(void) {
    /* Create HiTLS context */
    void *cfg = HITLS_CFG_NewTlsConfig();
    void *ctx = HITLS_New(cfg);
    if (ctx) HITLS_Free(ctx);
    if (cfg) HITLS_CFG_FreeConfig(cfg);
}
