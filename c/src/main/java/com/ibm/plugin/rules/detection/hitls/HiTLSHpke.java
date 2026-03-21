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
package com.ibm.plugin.rules.detection.hitls;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS HPKE (Hybrid Public Key Encryption) API.
 *
 * <p>HPKE (RFC 9180) = KEM + KDF + AEAD. Detects:
 *
 * <ul>
 *   <li>CRYPT_EAL_HpkeNewCtx — creates HPKE context
 *   <li>CRYPT_EAL_HpkeSetupBaseS — sender setup
 *   <li>CRYPT_EAL_HpkeSetupBaseR — receiver setup
 *   <li>CRYPT_EAL_HpkeSeal — encrypt + encapsulate
 *   <li>CRYPT_EAL_HpkeOpen — decrypt + decapsulate
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class HiTLSHpke {

    private HiTLSHpke() {
        // private
    }

    /** CRYPT_EAL_HpkeNewCtx — creates a new HPKE context. */
    private static final IDetectionRule<AstNode> HPKE_NEW_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_HpkeNewCtx")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HPKE"))
                    .withMethodParameter("CRYPT_HPKE_CipherSuite")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_HpkeSetupBaseS — HPKE sender setup (Base mode). */
    private static final IDetectionRule<AstNode> HPKE_SETUP_BASE_S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_HpkeSetupBaseS")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SETUP_BASE_S"))
                    .withMethodParameter("CRYPT_EAL_HpkeCtx")
                    .addDependingDetectionRules(List.of(HPKE_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_HpkeSetupBaseR — HPKE receiver setup (Base mode). */
    private static final IDetectionRule<AstNode> HPKE_SETUP_BASE_R =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_HpkeSetupBaseR")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SETUP_BASE_R"))
                    .withMethodParameter("CRYPT_EAL_HpkeCtx")
                    .addDependingDetectionRules(List.of(HPKE_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_HpkeSeal — HPKE single-shot encrypt. */
    private static final IDetectionRule<AstNode> HPKE_SEAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_HpkeSeal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEAL"))
                    .withMethodParameter("CRYPT_EAL_HpkeCtx")
                    .addDependingDetectionRules(List.of(HPKE_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_HpkeOpen — HPKE single-shot decrypt. */
    private static final IDetectionRule<AstNode> HPKE_OPEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_HpkeOpen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OPEN"))
                    .withMethodParameter("CRYPT_EAL_HpkeCtx")
                    .addDependingDetectionRules(List.of(HPKE_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(HPKE_NEW_CTX, HPKE_SETUP_BASE_S, HPKE_SETUP_BASE_R, HPKE_SEAL, HPKE_OPEN);
    }
}
