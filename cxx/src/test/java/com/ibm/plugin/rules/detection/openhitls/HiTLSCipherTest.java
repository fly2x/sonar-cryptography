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
package com.ibm.plugin.rules.detection.openhitls;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.cxx.CxxScanContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxTestBase;
import com.ibm.plugin.rules.detection.openhitls.cipher.HiTLSCipher;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Tests for HiTLS Cipher detection rules. Verifies that CRYPT_EAL_CipherNewCtx calls are correctly
 * detected.
 */
class HiTLSCipherTest extends CxxTestBase {

    public HiTLSCipherTest() {
        super(HiTLSCipher.rules());
    }

    @Test
    void testDetectionRulesNotEmpty() {
        assertThat(HiTLSCipher.rules()).isNotEmpty();
        assertThat(HiTLSCipher.rules()).hasSize(1);
    }

    @Test
    void testCipherRulesInAggregation() {
        assertThat(HiTLSDetectionRules.rules()).isNotEmpty();
        assertThat(HiTLSDetectionRules.rules()).containsAll(HiTLSCipher.rules());
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        assertThat(detectionStore).isNotNull();
        assertThat(detectionStore.getDetectionValues()).isNotEmpty();
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
    }
}
