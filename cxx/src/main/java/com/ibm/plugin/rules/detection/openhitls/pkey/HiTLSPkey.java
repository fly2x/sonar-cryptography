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
package com.ibm.plugin.rules.detection.openhitls.pkey;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS public key (asymmetric) API.
 *
 * <p>CRYPT_EAL_PkeyNewCtx uses AlgorithmFactory to capture the actual algorithm enum (e.g.,
 * CRYPT_PKEY_RSA, CRYPT_PKEY_ECDSA, CRYPT_PKEY_SM2). The other Pkey operations
 * (Sign/Verify/Gen/Encrypt/Decrypt) use ValueActionFactory with fixed labels since they don't carry
 * the algorithm ID as a parameter.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSPkey {

    private HiTLSPkey() {
        // private
    }

    /** CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_AlgorithmId id) — captures the algorithm enum. */
    private static final IDetectionRule<AstNode> PKEY_NEW_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_PkeyNewCtx")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_PkeySign — signs data using private key. */
    private static final IDetectionRule<AstNode> PKEY_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_PkeySign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(PKEY_NEW_CTX))
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_PkeyVerify — verifies a signature. */
    private static final IDetectionRule<AstNode> PKEY_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_PkeyVerify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(PKEY_NEW_CTX))
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_PkeyGen — generates a key pair. */
    private static final IDetectionRule<AstNode> PKEY_GEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_PkeyGen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(PKEY_NEW_CTX))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_PkeyEncrypt — encrypts data with public key. */
    private static final IDetectionRule<AstNode> PKEY_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_PkeyEncrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(PKEY_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_PkeyDecrypt — decrypts data with private key. */
    private static final IDetectionRule<AstNode> PKEY_DECRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_PkeyDecrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(PKEY_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(PKEY_NEW_CTX, PKEY_SIGN, PKEY_VERIFY, PKEY_GEN, PKEY_ENCRYPT, PKEY_DECRYPT);
    }
}
