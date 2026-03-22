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
package com.ibm.plugin.rules.detection.openhitls.digest;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS message digest (hash) API.
 *
 * <p>Detects usage of CRYPT_EAL_MdNewCtx(algorithmId) where algorithmId is a CRYPT_MD_* enum
 * constant. The AlgorithmFactory extracts the actual enum constant name (e.g., "CRYPT_MD_SHA256")
 * which is then resolved by CxxDigestContextTranslator to the concrete algorithm model.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSMessageDigest {

    private HiTLSMessageDigest() {
        // private
    }

    /**
     * CRYPT_EAL_MdNewCtx(CRYPT_MD_AlgorithmId id) — creates a new message digest context.
     * AlgorithmFactory captures the enum constant (e.g., CRYPT_MD_SHA256).
     */
    static final IDetectionRule<AstNode> MD_NEW_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MdNewCtx")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(MD_NEW_CTX);
    }
}
