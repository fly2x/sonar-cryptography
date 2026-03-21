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

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS MAC (Message Authentication Code) API.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>CRYPT_EAL_MacNewCtx(algorithmId) — creates a new MAC context
 * </ul>
 *
 * <p>CRYPT_MAC_* enums include: HMAC_MD5, HMAC_SHA1, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384,
 * HMAC_SHA512, HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512, HMAC_SM3, CMAC_AES128,
 * CMAC_AES256, etc.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSMac {

    private HiTLSMac() {
        // private
    }

    /** CRYPT_EAL_MacNewCtx(CRYPT_MAC_AlgorithmId id) Creates a new MAC context. */
    private static final IDetectionRule<AstNode> MAC_NEW_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MacNewCtx")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MAC"))
                    .withMethodParameter("CRYPT_MAC_AlgorithmId")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(MAC_NEW_CTX);
    }
}
