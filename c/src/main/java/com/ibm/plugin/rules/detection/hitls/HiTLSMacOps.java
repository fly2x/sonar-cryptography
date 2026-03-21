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
 * Detection rules for openHiTLS MAC operations that chain to {@link HiTLSMac#MAC_NEW_CTX}.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>CRYPT_EAL_MacInit — initialize MAC with key
 *   <li>CRYPT_EAL_MacUpdate — feed data into MAC
 *   <li>CRYPT_EAL_MacFinal — finalize and get MAC output
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class HiTLSMacOps {

    private HiTLSMacOps() {
        // private
    }

    private static final IDetectionRule<AstNode> MAC_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MacInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MAC_INIT"))
                    .withMethodParameter("CRYPT_EAL_MacCtx")
                    .addDependingDetectionRules(List.of(HiTLSMac.MAC_NEW_CTX))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MAC_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MacUpdate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MAC_UPDATE"))
                    .withMethodParameter("CRYPT_EAL_MacCtx")
                    .addDependingDetectionRules(List.of(HiTLSMac.MAC_NEW_CTX))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> MAC_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("CRYPT_EAL_MacFinal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MAC_FINAL"))
                    .withMethodParameter("CRYPT_EAL_MacCtx")
                    .addDependingDetectionRules(List.of(HiTLSMac.MAC_NEW_CTX))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(MAC_INIT, MAC_UPDATE, MAC_FINAL);
    }
}
