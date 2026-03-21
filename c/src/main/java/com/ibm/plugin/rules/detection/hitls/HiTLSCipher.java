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
 * Detection rules for openHiTLS symmetric cipher API.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>CRYPT_EAL_CipherNewCtx(algorithmId) — creates a new cipher context
 *   <li>CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, enc)
 * </ul>
 *
 * <p>CRYPT_CIPHER_* enums include: AES128_CBC, AES192_CBC, AES256_CBC, AES128_CTR, AES256_CTR,
 * AES128_GCM, AES256_GCM, SM4_XTS, SM4_CBC, SM4_CTR, SM4_GCM, CHACHA20_POLY1305, etc.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSCipher {

    private HiTLSCipher() {
        // private
    }

    /**
     * CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AlgorithmId id) Creates a new symmetric cipher context.
     */
    static final IDetectionRule<AstNode> CIPHER_NEW_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_CipherNewCtx")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER"))
                    .withMethodParameter("CRYPT_CIPHER_AlgorithmId")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(CIPHER_NEW_CTX);
    }
}
