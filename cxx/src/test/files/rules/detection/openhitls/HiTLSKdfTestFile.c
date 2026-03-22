/*
 * Test file for HiTLS KDF detection
 */
#include "crypt_eal_kdf.h"

void test_scrypt(void) {
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_SCRYPT); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_KdfFreeCtx(ctx);
    }
}

void test_pbkdf2(void) {
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_KdfFreeCtx(ctx);
    }
}

void test_hkdf(void) {
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_KdfFreeCtx(ctx);
    }
}
