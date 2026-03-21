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

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS public key (asymmetric) API.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>CRYPT_EAL_PkeyNewCtx(algorithmId) — creates a new pkey context
 * </ul>
 *
 * <p>CRYPT_PKEY_* enums include: RSA, DSA, DH, ECDSA, ECDH, ED25519, X25519, SM2, PAILLIER, etc.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSPkey {

    private HiTLSPkey() {
        // private
    }

    /** CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_AlgorithmId id) Creates a new public-key context. */
    private static final IDetectionRule<AstNode> PKEY_NEW_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_PkeyNewCtx")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKEY"))
                    .withMethodParameter("CRYPT_PKEY_AlgorithmId")
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(PKEY_NEW_CTX);
    }
}
