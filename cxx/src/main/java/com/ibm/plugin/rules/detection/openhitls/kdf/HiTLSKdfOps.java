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
package com.ibm.plugin.rules.detection.openhitls.kdf;

import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS KDF operations that chain to {@link HiTLSKdf#KDF_NEW_CTX}.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>CRYPT_EAL_KdfSetParam — set KDF parameters (salt, password, etc.)
 *   <li>CRYPT_EAL_KdfDerive — derive key material
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class HiTLSKdfOps {

    private HiTLSKdfOps() {
        // private
    }

    private static final IDetectionRule<AstNode> KDF_SET_PARAM =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_KdfSetParam")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KDF_SET_PARAM"))
                    .withMethodParameter("CRYPT_EAL_KdfCTX")
                    .addDependingDetectionRules(List.of(HiTLSKdf.KDF_NEW_CTX))
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> KDF_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_KdfDerive")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KDF_DERIVE"))
                    .withMethodParameter("CRYPT_EAL_KdfCTX")
                    .addDependingDetectionRules(List.of(HiTLSKdf.KDF_NEW_CTX))
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(KDF_SET_PARAM, KDF_DERIVE);
    }
}
