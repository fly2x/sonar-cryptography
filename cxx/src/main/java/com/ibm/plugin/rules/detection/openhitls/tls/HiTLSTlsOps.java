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
package com.ibm.plugin.rules.detection.openhitls.tls;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for openHiTLS TLS/DTLS operations that chain to {@link HiTLSTls#HITLS_NEW}.
 *
 * <p>Detects:
 *
 * <ul>
 *   <li>HITLS_Connect — initiate TLS handshake (client)
 *   <li>HITLS_Accept — accept TLS handshake (server)
 *   <li>HITLS_Read — read decrypted data from TLS connection
 *   <li>HITLS_Write — write data to TLS connection (encrypts)
 *   <li>HITLS_Close — close TLS connection
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class HiTLSTlsOps {

    private HiTLSTlsOps() {
        // private
    }

    private static final IDetectionRule<AstNode> HITLS_CONNECT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_Connect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS_CONNECT"))
                    .withMethodParameter("HITLS_Ctx")
                    .addDependingDetectionRules(List.of(HiTLSTls.HITLS_NEW))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HITLS_ACCEPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_Accept")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS_ACCEPT"))
                    .withMethodParameter("HITLS_Ctx")
                    .addDependingDetectionRules(List.of(HiTLSTls.HITLS_NEW))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HITLS_READ =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_Read")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS_READ"))
                    .withMethodParameter("HITLS_Ctx")
                    .addDependingDetectionRules(List.of(HiTLSTls.HITLS_NEW))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HITLS_WRITE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_Write")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS_WRITE"))
                    .withMethodParameter("HITLS_Ctx")
                    .addDependingDetectionRules(List.of(HiTLSTls.HITLS_NEW))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HITLS_CLOSE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("")
                    .forMethods("HITLS_Close")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS_CLOSE"))
                    .withMethodParameter("HITLS_Ctx")
                    .addDependingDetectionRules(List.of(HiTLSTls.HITLS_NEW))
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> "OpenHiTLS")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(HITLS_CONNECT, HITLS_ACCEPT, HITLS_READ, HITLS_WRITE, HITLS_CLOSE);
    }
}
