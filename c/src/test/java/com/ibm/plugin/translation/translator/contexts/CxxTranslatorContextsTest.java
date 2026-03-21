/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.translation.translator.contexts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Unit tests for all C/C++ context translators. */
class CxxTranslatorContextsTest {

    private static final AstNode MOCK = mock(AstNode.class);
    private static final DetectionLocation LOC =
            new DetectionLocation("test.c", 1, 0, List.of(), () -> "OpenHiTLS");

    private ValueAction<AstNode> val(String v) {
        return new ValueAction<>(v, MOCK);
    }

    // ========== Digest ==========

    @Test
    void testDigestKnownAlgorithms() {
        var t = new CxxDigestContextTranslator();
        for (String id :
                List.of(
                        "CRYPT_MD_SHA256",
                        "CRYPT_MD_SHA384",
                        "CRYPT_MD_SHA512",
                        "CRYPT_MD_SM3",
                        "CRYPT_MD_MD5",
                        "CRYPT_MD_SHA1")) {
            assertThat(t.translate(() -> "OpenHiTLS", val(id), new DigestContext(), LOC))
                    .as("Digest: %s", id)
                    .isPresent();
        }
    }

    @Test
    void testDigestUnknown() {
        assertThat(
                        new CxxDigestContextTranslator()
                                .translate(
                                        () -> "OpenHiTLS",
                                        val("UNKNOWN"),
                                        new DigestContext(),
                                        LOC))
                .isEmpty();
    }

    // ========== Cipher ==========

    @Test
    void testCipherKnownAlgorithms() {
        var t = new CxxCipherContextTranslator();
        for (String id :
                List.of(
                        "CRYPT_CIPHER_AES128_CBC",
                        "CRYPT_CIPHER_AES256_GCM",
                        "CRYPT_CIPHER_SM4_CBC",
                        "CRYPT_CIPHER_CHACHA20_POLY1305")) {
            assertThat(t.translate(() -> "OpenHiTLS", val(id), new CipherContext(), LOC))
                    .as("Cipher: %s", id)
                    .isPresent();
        }
    }

    // ========== Key ==========

    @Test
    void testKeyKnownAlgorithms() {
        var t = new CxxKeyContextTranslator();
        var ctx = new KeyContext(KeyContext.Kind.NONE);
        for (String id :
                List.of(
                        "CRYPT_PKEY_RSA",
                        "CRYPT_PKEY_DSA",
                        "CRYPT_PKEY_DH",
                        "CRYPT_PKEY_ECDSA",
                        "CRYPT_PKEY_ECDH",
                        "CRYPT_PKEY_ED25519",
                        "CRYPT_PKEY_X25519",
                        "CRYPT_PKEY_SM2")) {
            assertThat(t.translate(() -> "OpenHiTLS", val(id), ctx, LOC))
                    .as("Key: %s", id)
                    .isPresent();
        }
    }

    // ========== KDF ==========

    @Test
    void testKdfKnownAlgorithms() {
        var t = new CxxKdfContextTranslator();
        var ctx = new KeyDerivationFunctionContext();
        for (String id :
                List.of(
                        "CRYPT_KDF_SCRYPT",
                        "CRYPT_KDF_PBKDF2",
                        "CRYPT_KDF_HKDF",
                        "CRYPT_KDF_KDFTLS12")) {
            assertThat(t.translate(() -> "OpenHiTLS", val(id), ctx, LOC))
                    .as("KDF: %s", id)
                    .isPresent();
        }
    }

    @Test
    void testKdfTlsPrfName() {
        var result =
                new CxxKdfContextTranslator()
                        .translate(
                                () -> "OpenHiTLS",
                                val("CRYPT_KDF_KDFTLS12"),
                                new KeyDerivationFunctionContext(),
                                LOC);
        assertThat(result).isPresent();
        assertThat(result.get().asString()).contains("TLS-1.2-PRF");
    }

    // ========== PRNG ==========

    @Test
    void testPrngKnownAlgorithms() {
        var t = new CxxPRNGContextTranslator();
        for (String id : List.of("CRYPT_RAND_SHA256", "CRYPT_RAND_SHA384")) {
            var result = t.translate(() -> "OpenHiTLS", val(id), new PRNGContext(), LOC);
            assertThat(result).as("PRNG: %s", id).isPresent();
            assertThat(result.get().asString()).contains("DRBG");
        }
    }

    @Test
    void testPrngInvalid() {
        assertThat(
                        new CxxPRNGContextTranslator()
                                .translate(
                                        () -> "OpenHiTLS", val("NOT_RAND"), new PRNGContext(), LOC))
                .isEmpty();
    }

    // ========== Signature ==========

    @Test
    void testSignatureTranslator() {
        var t = new CxxSignatureContextTranslator();
        var signResult =
                t.translate(
                        () -> "OpenHiTLS",
                        val("SIGN"),
                        new com.ibm.engine.model.context.SignatureContext(),
                        LOC);
        assertThat(signResult).as("SIGN").isPresent();
        assertThat(signResult.get().asString()).contains("SIGN");

        var verifyResult =
                t.translate(
                        () -> "OpenHiTLS",
                        val("VERIFY"),
                        new com.ibm.engine.model.context.SignatureContext(),
                        LOC);
        assertThat(verifyResult).as("VERIFY").isPresent();
        assertThat(verifyResult.get().asString()).contains("VERIFY");
    }

    @Test
    void testSignatureTranslatorInvalid() {
        assertThat(
                        new CxxSignatureContextTranslator()
                                .translate(
                                        () -> "OpenHiTLS",
                                        val("UNKNOWN"),
                                        new com.ibm.engine.model.context.SignatureContext(),
                                        LOC))
                .isEmpty();
    }

    // ========== MAC ==========

    @Test
    void testMacKnownAlgorithms() {
        var t = new CxxMacContextTranslator();
        for (String id : List.of("CRYPT_MAC_HMAC_SHA256", "CRYPT_MAC_HMAC_SM3")) {
            assertThat(t.translate(() -> "OpenHiTLS", val(id), new DigestContext(), LOC))
                    .as("MAC: %s", id)
                    .isPresent();
        }
    }

    // ========== HPKE ==========

    @Test
    void testHpkeTranslator() {
        var t = new CxxHpkeContextTranslator();
        for (String id : List.of("HPKE", "SEAL", "OPEN", "SETUP_BASE_S", "SETUP_BASE_R")) {
            assertThat(t.translate(() -> "OpenHiTLS", val(id), new CipherContext(), LOC))
                    .as("HPKE: %s", id)
                    .isPresent();
        }
    }

    @Test
    void testHpkeTranslatorComposite() {
        var t = new CxxHpkeContextTranslator();
        var result = t.translate(() -> "OpenHiTLS", val("HPKE"), new CipherContext(), LOC);
        assertThat(result).isPresent();
        // HPKE should have child nodes (DHKEM, HKDF-SHA256)
        assertThat(result.get().hasChildren()).isTrue();
    }

    @Test
    void testHpkeTranslatorInvalid() {
        assertThat(
                        new CxxHpkeContextTranslator()
                                .translate(() -> "OpenHiTLS", val("AES"), new CipherContext(), LOC))
                .isEmpty();
    }

    // ========== Protocol ==========

    @Test
    void testProtocolTranslator() {
        var t = new CxxProtocolContextTranslator();
        for (String id : List.of("TLS", "DTLS", "HITLS")) {
            assertThat(
                            t.translate(
                                    () -> "OpenHiTLS",
                                    val(id),
                                    new com.ibm.engine.model.context.ProtocolContext(
                                            com.ibm.engine.model.context.ProtocolContext.Kind.TLS),
                                    LOC))
                    .as("Protocol: %s", id)
                    .isPresent();
        }
    }

    @Test
    void testProtocolTranslatorInvalid() {
        assertThat(
                        new CxxProtocolContextTranslator()
                                .translate(
                                        () -> "OpenHiTLS",
                                        val("UNKNOWN"),
                                        new com.ibm.engine.model.context.ProtocolContext(
                                                com.ibm.engine.model.context.ProtocolContext.Kind
                                                        .NONE),
                                        LOC))
                .isEmpty();
    }

    // ========== KeyAgreement ==========

    @Test
    void testKeyAgreementTranslator() {
        var t = new CxxKeyAgreementContextTranslator();
        for (String id : List.of("CRYPT_PKEY_DH", "CRYPT_PKEY_ECDH", "CRYPT_PKEY_X25519")) {
            assertThat(
                            t.translate(
                                    () -> "OpenHiTLS",
                                    val(id),
                                    new com.ibm.engine.model.context.KeyAgreementContext(),
                                    LOC))
                    .as("KA: %s", id)
                    .isPresent();
        }
    }
}
