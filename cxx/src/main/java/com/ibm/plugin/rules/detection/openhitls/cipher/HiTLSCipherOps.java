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
package com.ibm.plugin.rules.detection.openhitls.cipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS cipher operations that chain to {@link HiTLSCipher#CIPHER_NEW_CTX}.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>CRYPT_EAL_CipherInit — initialize cipher with key/iv
 *   <li>CRYPT_EAL_CipherUpdate — process data blocks
 *   <li>CRYPT_EAL_CipherFinal — finalize cipher operation
 * </ul>
 *
 * <p>Each operation links back to {@code CRYPT_EAL_CipherNewCtx} via the {@code
 * CRYPT_EAL_CipherCtx} parameter to propagate the algorithm identity.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSCipherOps {

    private HiTLSCipherOps() {
        // private
    }

    /** CRYPT_EAL_CipherInit — initializes cipher context with key and IV. */
    private static final IDetectionRule<AstNode> CIPHER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_CipherInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER_INIT"))
                    .withMethodParameter("CRYPT_EAL_CipherCtx")
                    .addDependingDetectionRules(List.of(HiTLSCipher.CIPHER_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_CipherUpdate — processes data blocks. */
    private static final IDetectionRule<AstNode> CIPHER_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_CipherUpdate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER_UPDATE"))
                    .withMethodParameter("CRYPT_EAL_CipherCtx")
                    .addDependingDetectionRules(List.of(HiTLSCipher.CIPHER_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_CipherFinal — finalizes cipher operation. */
    private static final IDetectionRule<AstNode> CIPHER_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_CipherFinal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER_FINAL"))
                    .withMethodParameter("CRYPT_EAL_CipherCtx")
                    .addDependingDetectionRules(List.of(HiTLSCipher.CIPHER_NEW_CTX))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(CIPHER_INIT, CIPHER_UPDATE, CIPHER_FINAL);
    }
}
