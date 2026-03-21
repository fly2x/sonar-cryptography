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
 * Detection rules for openHiTLS message digest operations that chain to {@link
 * HiTLSMessageDigest#MD_NEW_CTX}.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>CRYPT_EAL_MdInit — initialize digest context
 *   <li>CRYPT_EAL_MdUpdate — feed data into digest
 *   <li>CRYPT_EAL_MdFinal — finalize and get digest output
 * </ul>
 *
 * <p>Each operation links back to {@code CRYPT_EAL_MdNewCtx} via the {@code CRYPT_EAL_MdCTX}
 * parameter to propagate the algorithm identity.
 */
@SuppressWarnings("java:S1192")
public final class HiTLSMdOps {

    private HiTLSMdOps() {
        // private
    }

    /** CRYPT_EAL_MdInit — initializes the message digest context. */
    private static final IDetectionRule<AstNode> MD_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MdInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD_INIT"))
                    .withMethodParameter("CRYPT_EAL_MdCTX")
                    .addDependingDetectionRules(List.of(HiTLSMessageDigest.MD_NEW_CTX))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_MdUpdate — feeds data into the digest. */
    private static final IDetectionRule<AstNode> MD_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MdUpdate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD_UPDATE"))
                    .withMethodParameter("CRYPT_EAL_MdCTX")
                    .addDependingDetectionRules(List.of(HiTLSMessageDigest.MD_NEW_CTX))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    /** CRYPT_EAL_MdFinal — finalizes and produces the digest output. */
    private static final IDetectionRule<AstNode> MD_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MdFinal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD_FINAL"))
                    .withMethodParameter("CRYPT_EAL_MdCTX")
                    .addDependingDetectionRules(List.of(HiTLSMessageDigest.MD_NEW_CTX))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(MD_INIT, MD_UPDATE, MD_FINAL);
    }
}
