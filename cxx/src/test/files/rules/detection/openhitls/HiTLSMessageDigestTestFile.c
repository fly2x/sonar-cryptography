/*
 * Test file for HiTLS Message Digest detection
 * Tests detection of CRYPT_EAL_MdNewCtx calls with various algorithm IDs.
 */
#include "crypt_eal_md.h"

void test_sha256(void) {
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_MdInit(ctx);
        CRYPT_EAL_MdUpdate(ctx, "hello", 5);
        uint8_t out[32];
        uint32_t outLen = sizeof(out);
        CRYPT_EAL_MdFinal(ctx, out, &outLen);
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

void test_sha384(void) {
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA384); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

void test_sm3(void) {
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}
