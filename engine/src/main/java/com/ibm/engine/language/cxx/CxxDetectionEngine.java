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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxAstNodeHelper;
import org.sonar.cxx.utils.CxxConstantUtils;

/**
 * Detection engine for C/C++. Traverses AstNode trees to find function calls matching detection
 * rules, extracts parameters, and resolves constant values.
 *
 * <p>This is simpler than the Go/Java engines because C has flat function calls (no method
 * chaining, no composite literals, no constructors).
 */
@SuppressWarnings("java:S3776")
public final class CxxDetectionEngine implements IDetectionEngine<AstNode, Symbol> {

    @Nonnull
    private final DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
            detectionStore;

    @Nonnull private final Handler<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> handler;

    public CxxDetectionEngine(
            @Nonnull
                    DetectionStore<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext>
                            detectionStore,
            @Nonnull Handler<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull AstNode tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode tree) {
        // Traverse the AST tree looking for function calls
        traverseForFunctionCalls(traceSymbol, tree);
    }

    /**
     * Recursively traverses the AST looking for function call nodes that match the current
     * detection rule.
     */
    private void traverseForFunctionCalls(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode node) {
        // Check if this node is a function call that matches the detection rule
        if (CxxAstNodeHelper.isFunctionCall(node)) {
            handler.addCallToCallStack(node, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(node, handler.getLanguageSupport().translation())) {
                analyseExpression(node);
                return; // Don't recurse into matched function call's children
            }
        }
        // Recurse into children
        for (AstNode child : node.getChildren()) {
            traverseForFunctionCalls(traceSymbol, child);
        }
    }

    /** Analyzes a matched function call expression, extracting parameters. */
    private void analyseExpression(@Nonnull AstNode functionCall) {
        DetectionRule<AstNode> detectionRule = emitDetectionAndGetRule(functionCall);
        if (detectionRule == null) {
            return;
        }

        List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(functionCall);
        if (arguments == null || arguments.isEmpty()) {
            return;
        }

        int index = 0;
        for (Parameter<AstNode> parameter : detectionRule.parameters()) {
            if (arguments.size() <= index) {
                index++;
                continue;
            }
            processParameter(parameter, arguments.get(index), functionCall);
            index++;
        }
    }

    @Nullable private DetectionRule<AstNode> emitDetectionAndGetRule(@Nonnull AstNode tree) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
            return null;
        }

        DetectionRule<AstNode> detectionRule =
                (DetectionRule<AstNode>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
        }
        return detectionRule;
    }

    /** Processes a single parameter by resolving its value. */
    private void processParameter(
            @Nonnull Parameter<AstNode> parameter,
            @Nonnull AstNode expression,
            @Nonnull AstNode parentTree) {

        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<AstNode> detectableParameter =
                    (DetectableParameter<AstNode>) parameter;
            List<ResolvedValue<Object, AstNode>> resolvedValues =
                    resolveValuesInInnerScope(
                            Object.class, expression, detectableParameter.getiValueFactory());
            if (resolvedValues.isEmpty()) {
                resolveValuesInOuterScope(expression, detectableParameter);
            } else {
                resolvedValues.stream()
                        .map(
                                resolvedValue ->
                                        new ValueDetection<>(
                                                resolvedValue,
                                                detectableParameter,
                                                parentTree,
                                                parentTree))
                        .forEach(detectionStore::onReceivingNewDetection);
            }
        } else if (!parameter.getDetectionRules().isEmpty()) {
            // Depending detection rules: dispatch sub-detection
            detectionStore.onDetectedDependingParameter(
                    parameter, expression, DetectionStore.Scope.EXPRESSION);
        }
    }

    @Nullable @Override
    public AstNode extractArgumentFromMethodCaller(
            @Nonnull AstNode methodDefinition,
            @Nonnull AstNode methodInvocation,
            @Nonnull AstNode methodParameterIdentifier) {
        // Not commonly needed for C crypto API detection (no method chaining)
        return null;
    }

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, AstNode>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode expression,
            @Nullable IValueFactory<AstNode> valueFactory) {
        return resolveValues(clazz, expression, valueFactory);
    }

    /** Resolves values from C AST, using CxxConstantUtils for enum/const resolution. */
    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, AstNode>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode expression,
            @Nullable IValueFactory<AstNode> valueFactory) {

        // Try CxxConstantUtils first — resolves enum values, const variables, literals
        Object constantValue = CxxConstantUtils.resolveAsConstant(expression);
        if (constantValue != null) {
            O castValue = castValue(clazz, constantValue);
            if (castValue != null) {
                return List.of(new ResolvedValue<>(castValue, expression));
            }
        }

        // Fallback: try token value (identifiers, string literals)
        String tokenValue = expression.getTokenValue();
        if (tokenValue != null && !tokenValue.isEmpty()) {
            // Strip quotes from string literals
            if (tokenValue.startsWith("\"") && tokenValue.endsWith("\"")) {
                tokenValue = tokenValue.substring(1, tokenValue.length() - 1);
            }
            O castValue = castValue(clazz, tokenValue);
            if (castValue != null) {
                return List.of(new ResolvedValue<>(castValue, expression));
            }
        }

        return Collections.emptyList();
    }

    @SuppressWarnings("unchecked")
    @Nullable private <O> O castValue(@Nonnull Class<O> clazz, @Nonnull Object value) {
        try {
            if (clazz == Object.class) {
                return (O) value;
            }
            if (clazz == String.class) {
                return clazz.cast(value.toString());
            }
            if (clazz == Integer.class && value instanceof Number number) {
                return (O) Integer.valueOf(number.intValue());
            }
            if (clazz == Integer.class && value instanceof String stringValue) {
                try {
                    return (O) Integer.valueOf(stringValue);
                } catch (NumberFormatException e) {
                    return null;
                }
            }
            return clazz.cast(value);
        } catch (ClassCastException e) {
            return null;
        }
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull AstNode expression, @Nonnull Parameter<AstNode> parameter) {
        // Cross-function value resolution is not supported for C
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode methodDefinition,
            @Nonnull Parameter<AstNode> parameter) {
        // Not commonly needed for C crypto API detection
    }

    @Nullable @Override
    public <O> ResolvedValue<O, AstNode> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode enumClassDefinition,
            @Nonnull LinkedList<AstNode> selections) {
        // Try CxxConstantUtils to resolve enum
        Object value = CxxConstantUtils.resolveAsConstant(enumClassDefinition);
        if (value != null) {
            O castValue = castValue(clazz, value);
            if (castValue != null) {
                return new ResolvedValue<>(castValue, enumClassDefinition);
            }
        }
        return null;
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getAssignedSymbol(@Nonnull AstNode expression) {
        Symbol symbol = CxxAstNodeHelper.getAssignedSymbol(expression);
        if (symbol != null) {
            return Optional.of(TraceSymbol.createFrom(symbol));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getMethodInvocationParameterSymbol(
            @Nonnull AstNode methodInvocation, @Nonnull Parameter<AstNode> parameter) {
        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(methodInvocation);
            if (arguments != null
                    && parameter.getIndex() >= 0
                    && parameter.getIndex() < arguments.size()) {
                AstNode arg = arguments.get(parameter.getIndex());
                Symbol symbol = CxxAstNodeHelper.getAssignedSymbol(arg);
                if (symbol != null) {
                    return Optional.of(TraceSymbol.createFrom(symbol));
                }
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getNewClassParameterSymbol(
            @Nonnull AstNode newClass, @Nonnull Parameter<AstNode> parameter) {
        // C doesn't have new class syntax — treat as function call
        return getMethodInvocationParameterSymbol(newClass, parameter);
    }

    @Override
    public boolean isInvocationOnVariable(
            AstNode methodInvocation, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        Symbol variable = variableSymbol.getSymbol();
        if (variable == null) {
            return false;
        }
        return CxxAstNodeHelper.isInvocationOnVariable(methodInvocation, variable, true);
    }

    @Override
    public boolean isInitForVariable(
            AstNode newClass, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        // C doesn't have initialization patterns like Java's "new ClassName()"
        return false;
    }
}
