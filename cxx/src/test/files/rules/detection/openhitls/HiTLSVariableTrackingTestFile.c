/*
 * Comprehensive test file for variable tracking in the CXX detection engine.
 * Each scenario tests a different code pattern for cryptographic API calls.
 */
#include "crypt_eal_md.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_mac.h"

/* ===== Scenario 1: Direct enum constant (baseline) ===== */
void scenario1_direct_enum(void) {
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    if (ctx != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

/* ===== Scenario 2: Variable declared with initializer ===== */
void scenario2_variable_init(void) {
    CRYPT_MD_AlgId mdId = CRYPT_MD_SM3;
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(mdId);
    if (ctx != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

/* ===== Scenario 3: Variable assigned separately ===== */
void scenario3_variable_assign(void) {
    CRYPT_MD_AlgId mdId;
    mdId = CRYPT_MD_SHA384;
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(mdId);
    if (ctx != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

/* ===== Scenario 4: Variable with Cipher API ===== */
void scenario4_cipher_variable(void) {
    CRYPT_CIPHER_AlgId cipherId = CRYPT_CIPHER_AES256_GCM;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(cipherId);
    if (ctx != NULL) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
}

/* ===== Scenario 5: Variable with PKey API ===== */
void scenario5_pkey_variable(void) {
    CRYPT_PKEY_AlgId algId = CRYPT_PKEY_ECDSA;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(algId);
    if (ctx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
    }
}

/* ===== Scenario 6: Variable with MAC API ===== */
void scenario6_mac_variable(void) {
    CRYPT_MAC_AlgId macId = CRYPT_MAC_HMAC_SHA256;
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(macId);
    if (ctx != NULL) {
        CRYPT_EAL_MacFreeCtx(ctx);
    }
}

/* ===== Scenario 7: Multiple variables in same function ===== */
void scenario7_multiple_variables(void) {
    CRYPT_MD_AlgId mdId1 = CRYPT_MD_SHA256;
    CRYPT_MD_AlgId mdId2 = CRYPT_MD_SM3;
    CRYPT_EAL_MdCtx *ctx1 = CRYPT_EAL_MdNewCtx(mdId1);
    CRYPT_EAL_MdCtx *ctx2 = CRYPT_EAL_MdNewCtx(mdId2);
    if (ctx1 != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx1);
    }
    if (ctx2 != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx2);
    }
}

/* ===== Scenario 8: Variable reassigned before use ===== */
void scenario8_reassign(void) {
    CRYPT_MD_AlgId mdId = CRYPT_MD_SHA256;
    mdId = CRYPT_MD_SHA384;
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(mdId);
    if (ctx != NULL) {
        CRYPT_EAL_MdFreeCtx(ctx);
    }
}

/* ===== Scenario 9: Direct enum with multiple APIs in one func ===== */
void scenario9_mixed(void) {
    CRYPT_EAL_MdCtx *md = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    CRYPT_EAL_CipherCtx *cipher = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    if (md != NULL) CRYPT_EAL_MdFreeCtx(md);
    if (cipher != NULL) CRYPT_EAL_CipherFreeCtx(cipher);
}
