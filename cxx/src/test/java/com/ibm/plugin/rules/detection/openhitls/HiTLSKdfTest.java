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
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxTestBase;
import com.ibm.plugin.rules.detection.openhitls.kdf.HiTLSKdf;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

class HiTLSKdfTest extends CxxTestBase {

    public HiTLSKdfTest() {
        super(HiTLSKdf.rules());
    }

    @Test
    void testDetectionRulesNotEmpty() {
        assertThat(HiTLSKdf.rules()).isNotEmpty();
        assertThat(HiTLSKdf.rules()).hasSize(1);
    }

    @Test
    void testKdfRulesInAggregation() {
        assertThat(HiTLSDetectionRules.rules()).containsAll(HiTLSKdf.rules());
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
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
    }
}
