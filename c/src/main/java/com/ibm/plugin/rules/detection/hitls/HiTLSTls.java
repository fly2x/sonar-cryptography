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

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS TLS configuration API.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>HITLS_CFG_NewTlsConfig — creates TLS configuration
 *   <li>HITLS_CFG_NewDtlsConfig — creates DTLS configuration
 *   <li>HITLS_New — creates a new HiTLS context
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class HiTLSTls {

    private HiTLSTls() {
        // private
    }

    static final IDetectionRule<AstNode> TLS_CONFIG =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_CFG_NewTlsConfig")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withMethodParameter("void")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    static final IDetectionRule<AstNode> DTLS_CONFIG =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_CFG_NewDtlsConfig")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLS"))
                    .withMethodParameter("void")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    static final IDetectionRule<AstNode> HITLS_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_New")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HITLS"))
                    .withMethodParameter("HITLS_Config")
                    .addDependingDetectionRules(List.of(TLS_CONFIG, DTLS_CONFIG))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(TLS_CONFIG, DTLS_CONFIG, HITLS_NEW);
    }
}
