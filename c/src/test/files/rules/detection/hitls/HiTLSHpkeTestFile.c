/*
 * Test file for HiTLS HPKE detection
 */
#include "crypt_eal_hpke.h"

void test_hpke(void) {
    CRYPT_HPKE_CipherSuite suite = {0};
    CRYPT_EAL_HpkeCtx *ctx = CRYPT_EAL_HpkeNewCtx(suite); // Noncompliant
    if (ctx != NULL) {
        CRYPT_EAL_HpkeFreeCtx(ctx);
    }
}
