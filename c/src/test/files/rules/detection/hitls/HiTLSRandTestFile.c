/*
 * Test file for HiTLS Random detection
 */
#include "crypt_eal_rand.h"

void test_rand_sha256(void) {
    CRYPT_EAL_RandCtx *ctx = CRYPT_EAL_RandNewCtx(CRYPT_RAND_SHA256); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_RandFreeCtx(ctx);
    }
}

void test_rand_hmac_sha256(void) {
    CRYPT_EAL_RandCtx *ctx = CRYPT_EAL_RandNewCtx(CRYPT_RAND_HMAC_SHA256); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_RandFreeCtx(ctx);
    }
}
