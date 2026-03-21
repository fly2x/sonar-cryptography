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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IDetectionRule;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Tests for HiTLS TLS/DTLS detection rules. */
class HiTLSTlsTest {

    @Test
    void testRuleCount() {
        List<IDetectionRule<AstNode>> rules = HiTLSTls.rules();
        // 3 rules: HITLS_CFG_NewTlsConfig, HITLS_CFG_NewDtlsConfig, HITLS_New
        assertThat(rules).hasSize(3);
    }

    @Test
    void testAllRulesAggregated() {
        // 8 categories: Md(1) + Cipher(1) + Mac(1) + Pkey(6) + Kdf(1) + Rand(1) + Hpke(1) + Tls(3)
        // = 15
        assertThat(HiTLSDetectionRules.rules()).hasSize(25);
    }

    @Test
    void testRulesNotEmpty() {
        assertThat(HiTLSTls.rules()).isNotEmpty();
        HiTLSTls.rules().forEach(rule -> assertThat(rule).isNotNull());
    }
}
