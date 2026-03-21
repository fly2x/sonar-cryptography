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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.plugin.rules.detection.CxxDetectionRules;
import com.ibm.plugin.rules.detection.hitls.HiTLSDetectionRules;
import org.junit.jupiter.api.Test;

/**
 * Integration test verifying the full detection rule chain wiring. Tests that all rule categories
 * are properly wired: HiTLSDetectionRules → CxxDetectionRules → CxxRuleList.
 */
class CxxDetectionRulesIntegrationTest {

    @Test
    void testHiTLSDetectionRulesContainAllCategories() {
        // 6 categories: Md(1) + Cipher(1) + Mac(1) + Pkey(3) + Kdf(1) + Rand(1) = 8
        assertThat(HiTLSDetectionRules.rules()).hasSize(30);
    }

    @Test
    void testCxxDetectionRulesContainHiTLSRules() {
        assertThat(CxxDetectionRules.rules()).containsAll(HiTLSDetectionRules.rules());
    }

    @Test
    void testCxxRuleListNotEmpty() {
        assertThat(CxxRuleList.getCxxChecks()).isNotEmpty();
    }

    @Test
    void testTranslationProcessCanBeCreated() {
        var process = new com.ibm.plugin.translation.CxxTranslationProcess(java.util.List.of());
        assertThat(process).isNotNull();
    }

    @Test
    void testAggregatorCanBeResetAndQueried() {
        CxxAggregator.reset();
        assertThat(CxxAggregator.getDetectedNodes()).isNotNull();
        assertThat(CxxAggregator.getDetectedNodes()).isEmpty();
    }
}
