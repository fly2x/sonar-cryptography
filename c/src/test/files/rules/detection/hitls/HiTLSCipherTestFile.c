/*
 * Test file for HiTLS Cipher detection
 * Tests detection of CRYPT_EAL_CipherNewCtx calls with various cipher algorithm IDs.
 */
#include "crypt_eal_cipher.h"

void test_aes256_gcm(void) {
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES256_GCM); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}

void test_sm4_cbc(void) {
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}

void test_chacha20_poly1305(void) {
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}
