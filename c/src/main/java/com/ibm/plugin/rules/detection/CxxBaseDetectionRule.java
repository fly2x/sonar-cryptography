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
package com.ibm.plugin.rules.detection;

import com.ibm.common.IObserver;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.cxx.CxxScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.translation.CxxTranslationProcess;
import com.ibm.plugin.translation.reorganizer.CxxReorganizerRules;
import com.ibm.rules.IReportableDetectionRule;
import com.ibm.rules.issue.Issue;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Base detection rule for C/C++ cryptographic patterns. Uses sonar-cxx's SquidCheck as the base
 * class and subscribes as a Finding observer to receive detection results.
 */
public abstract class CxxBaseDetectionRule extends SquidCheck<Grammar>
        implements IObserver<Finding<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>>,
                IReportableDetectionRule<AstNode> {

    private final boolean isInventory;
    @Nonnull protected final CxxTranslationProcess cxxTranslationProcess;
    @Nonnull protected final List<IDetectionRule<AstNode>> detectionRules;

    protected CxxBaseDetectionRule() {
        this.isInventory = false;
        this.detectionRules = CxxDetectionRules.rules();
        this.cxxTranslationProcess = new CxxTranslationProcess(CxxReorganizerRules.rules());
    }

    protected CxxBaseDetectionRule(
            final boolean isInventory,
            @Nonnull List<IDetectionRule<AstNode>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.isInventory = isInventory;
        this.detectionRules = detectionRules;
        this.cxxTranslationProcess = new CxxTranslationProcess(reorganizerRules);
    }

    @Override
    public void visitFile(@javax.annotation.Nullable AstNode astNode) {
        if (astNode == null) {
            return;
        }
        // Create scan context from the visitor context
        CxxScanContext scanContext = new CxxScanContext(getContext(), getContext().getFile());
        // Run all detection rules against the file's AST
        detectionRules.forEach(
                rule -> {
                    DetectionExecutive<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
                            detectionExecutive =
                                    CxxAggregator.getLanguageSupport()
                                            .createDetectionExecutive(astNode, rule, scanContext);
                    detectionExecutive.subscribe(this);
                    detectionExecutive.start();
                });
    }

    /**
     * Updates the output with the translated nodes resulting from a finding.
     *
     * @param finding A finding containing detection store information.
     */
    @Override
    public void update(
            @Nonnull Finding<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> finding) {
        List<INode> nodes = cxxTranslationProcess.initiate(finding.detectionStore());
        if (isInventory) {
            CxxAggregator.addNodes(nodes);
        }
        // report
        this.report(finding.getMarkerTree(), nodes)
                .forEach(
                        issue ->
                                finding.detectionStore()
                                        .getScanContext()
                                        .reportIssue(this, issue.tree(), issue.message()));
    }

    @Override
    @Nonnull
    public List<Issue<AstNode>> report(
            @Nonnull AstNode markerTree, @Nonnull List<INode> translatedNodes) {
        // override by higher level rule, to report an issue
        return Collections.emptyList();
    }
}
