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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.language.cxx.CxxScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.rules.CxxInventoryRule;
import com.ibm.plugin.rules.detection.CxxDetectionRules;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Base class for C/C++ detection rule unit tests. Follows the same pattern as Go's TestBase:
 * extends CxxInventoryRule and captures Finding updates for assertions.
 */
public abstract class CxxTestBase extends CxxInventoryRule {

    @Nonnull
    private final DetectionStoreLogger<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
            detectionStoreLogger = new DetectionStoreLogger<>();

    private int findingId = 0;

    public CxxTestBase(@Nonnull List<IDetectionRule<AstNode>> detectionRules) {
        super(detectionRules);
    }

    public CxxTestBase() {
        super(CxxDetectionRules.rules());
    }

    @BeforeEach
    public void resetState() {
        CxxAggregator.reset();
        findingId = 0;
    }

    @Override
    public void update(
            @Nonnull Finding<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> finding) {
        final DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> detectionStore =
                finding.detectionStore();
        detectionStoreLogger.print(detectionStore);

        List<INode> nodes = cxxTranslationProcess.initiate(detectionStore);
        asserts(findingId, detectionStore, nodes);
        findingId++;
        // report
        this.report(finding.getMarkerTree(), nodes)
                .forEach(
                        issue ->
                                finding.detectionStore()
                                        .getScanContext()
                                        .reportIssue(this, issue.tree(), issue.message()));
    }

    public abstract void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes);

    @Nullable public DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> getStoreOfValueType(
            @Nonnull final Class<? extends IValue> valueType,
            @Nonnull
                    List<DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>>
                            detectionStores) {
        Optional<DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>>
                relevantStore =
                        detectionStores.stream()
                                .filter(
                                        store ->
                                                store.getDetectionValues().stream()
                                                        .anyMatch(
                                                                value ->
                                                                        value.getClass()
                                                                                .equals(valueType)))
                                .findFirst();
        return relevantStore.orElseGet(
                () ->
                        detectionStores.stream()
                                .map(
                                        store ->
                                                Optional.ofNullable(
                                                        getStoreOfValueType(
                                                                valueType, store.getChildren())))
                                .filter(Optional::isPresent)
                                .map(Optional::get)
                                .findFirst()
                                .orElse(null));
    }
}
