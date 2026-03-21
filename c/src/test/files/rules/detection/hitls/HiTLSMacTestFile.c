/*
 * Test file for HiTLS MAC detection
 * Tests detection of CRYPT_EAL_MacNewCtx calls with various MAC algorithm IDs.
 */
#include "crypt_eal_mac.h"

void test_hmac_sha256(void) {
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SHA256); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_MacFreeCtx(ctx);
    }
}

void test_hmac_sm3(void) {
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SM3); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_MacFreeCtx(ctx);
    }
}
