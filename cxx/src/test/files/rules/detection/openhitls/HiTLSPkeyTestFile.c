/*
 * Test file for HiTLS Public Key detection
 * Tests detection of CRYPT_EAL_PkeyNewCtx calls with various pkey algorithm IDs.
 */
#include "crypt_eal_pkey.h"

void test_rsa(void) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

void test_ecdsa(void) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

void test_sm2(void) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

void test_ed25519(void) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED25519); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}
