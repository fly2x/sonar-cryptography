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
package com.ibm.engine.language.cxx;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.EnumMatcher;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IBaseMethodVisitorFactory;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.LinkedList;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * Language support implementation for C/C++. Maps sonar-cxx types directly to sonar-cryptography
 * engine generics:
 *
 * <ul>
 *   <li>R = SquidCheck&lt;Grammar&gt;
 *   <li>T = AstNode
 *   <li>S = Symbol
 *   <li>P = CxxScanContext
 * </ul>
 */
public final class CxxLanguageSupport
        implements ILanguageSupport<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> {

    @Nonnull private final Handler<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> handler;
    @Nonnull private final CxxLanguageTranslation translation;

    public CxxLanguageSupport() {
        this.handler = new Handler<>(this);
        this.translation = new CxxLanguageTranslation();
    }

    @Nonnull
    @Override
    public ILanguageTranslation<AstNode> translation() {
        return translation;
    }

    @Nonnull
    @Override
    public DetectionExecutive<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
            createDetectionExecutive(
                    @Nonnull AstNode tree,
                    @Nonnull IDetectionRule<AstNode> detectionRule,
                    @Nonnull IScanContext<SquidCheck<Grammar>, AstNode> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Nonnull
    @Override
    public IDetectionEngine<AstNode, Symbol> createDetectionEngineInstance(
            @Nonnull
                    DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
                            detectionStore) {
        return new CxxDetectionEngine(detectionStore, this.handler);
    }

    @Nonnull
    @Override
    public IBaseMethodVisitorFactory<AstNode, Symbol> getBaseMethodVisitorFactory() {
        return CxxBaseMethodVisitor::new;
    }

    @Nonnull
    @Override
    public Optional<AstNode> getEnclosingMethod(@Nonnull AstNode expression) {
        AstNode enclosing = CxxAstNodeHelper.getEnclosingFunction(expression);
        return Optional.ofNullable(enclosing);
    }

    @Nullable @Override
    public MethodMatcher<AstNode> createMethodMatcherBasedOn(@Nonnull AstNode methodDefinition) {
        // For C, create a matcher based on function name
        String functionName = CxxAstNodeHelper.getFunctionCallName(methodDefinition);
        if (functionName == null || functionName.isEmpty()) {
            return null;
        }
        // C global functions: empty invocation object name, function name, ANY parameters
        LinkedList<String> parameterTypeList = new LinkedList<>();
        parameterTypeList.add(ANY);
        return new MethodMatcher<>("", functionName, parameterTypeList);
    }

    @Nullable @Override
    public EnumMatcher<AstNode> createSimpleEnumMatcherFor(
            @Nonnull AstNode enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> enumIdentifierName =
                translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return enumIdentifierName.<EnumMatcher<AstNode>>map(EnumMatcher::new).orElse(null);
    }
}
