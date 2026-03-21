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

import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rule for openHiTLS KDF API: CRYPT_EAL_KdfNewCtx. Detects calls like:
 * CRYPT_EAL_KdfNewCtx(CRYPT_KDF_SCRYPT)
 *
 * <p>CRYPT_KDF_* enums include: SCRYPT, PBKDF2, KDFTLS12, HKDF.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSKdf {

    private HiTLSKdf() {
        // private
    }

    private static final IDetectionRule<AstNode> KDF_NEW_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_KdfNewCtx")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KDF"))
                    .withMethodParameter("CRYPT_KDF_AlgId")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(KDF_NEW_CTX);
    }
}
