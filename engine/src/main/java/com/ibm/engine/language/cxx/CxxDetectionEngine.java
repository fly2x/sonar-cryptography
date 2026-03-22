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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(CxxDetectionEngine.class);

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
     * Traverse the AST to find function calls matching the detection rule. For each match, extract
     * and resolve parameters.
     */
    private void traverseForFunctionCalls(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode node) {
        if (CxxAstNodeHelper.isFunctionCall(node)) {
            if (detectionStore
                    .getDetectionRule()
                    .match(node, handler.getLanguageSupport().translation())) {
                LOGGER.debug(
                        "[DIAG] Rule matched function: {} at line {}",
                        node.getTokenValue(),
                        node.getTokenLine());
                analyseExpression(traceSymbol, node);
            }
        }
        for (AstNode child : node.getChildren()) {
            traverseForFunctionCalls(traceSymbol, child);
        }
    }

    /**
     * Analyze a matched function call: extract each parameter as defined by the detection rule and
     * resolve its value.
     */
    @SuppressWarnings("java:S3776")
    private void analyseExpression(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode functionCall) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            MethodDetection<AstNode> methodDetection = new MethodDetection<>(functionCall, null);
            detectionStore.onReceivingNewDetection(methodDetection);
            return;
        }

        DetectionRule<AstNode> detectionRule =
                (DetectionRule<AstNode>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            MethodDetection<AstNode> methodDetection = new MethodDetection<>(functionCall, null);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(functionCall);
        int index = 0;
        for (Parameter<AstNode> parameter : detectionRule.parameters()) {
            if (index >= arguments.size()) {
                break;
            }
            AstNode expression = arguments.get(index);
            processParameter(parameter, expression, functionCall);
            index++;
        }
    }

    /**
     * Process a single parameter of a matched function call. If the parameter is detectable,
     * resolve its value; otherwise, handle depending detection rules.
     */
    private void processParameter(
            @Nonnull Parameter<AstNode> parameter,
            @Nonnull AstNode expression,
            @Nonnull AstNode parentTree) {
        LOGGER.debug(
                "[DIAG] processParameter: paramType={}, exprToken={}, exprNodeType={}",
                parameter.getClass().getSimpleName(),
                expression.getTokenValue(),
                expression.getName());

        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<AstNode> detectableParameter =
                    (DetectableParameter<AstNode>) parameter;
            LOGGER.debug(
                    "[DIAG]   DetectableParameter: factory={}",
                    detectableParameter.getiValueFactory() != null
                            ? detectableParameter.getiValueFactory().getClass().getSimpleName()
                            : "null");
            // Try to resolve value in inner scope
            List<ResolvedValue<Object, AstNode>> resolvedValues =
                    resolveValuesInInnerScope(
                            Object.class, expression, detectableParameter.getiValueFactory());
            LOGGER.debug(
                    "[DIAG]   resolvedValues count={}, values=[{}]",
                    resolvedValues.size(),
                    resolvedValues.stream()
                            .map(
                                    rv ->
                                            rv.value()
                                                    + "("
                                                    + rv.value().getClass().getSimpleName()
                                                    + ")")
                            .reduce((a, b) -> a + ", " + b)
                            .orElse(""));
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
        return resolveValues(clazz, expression, valueFactory, 0);
    }

    /**
     * Resolves values from C AST with variable tracking.
     *
     * <p>Resolution order: 1. CxxConstantUtils — resolves enum values, const variables, literals 2.
     * Check if token looks like a known C enum constant (CRYPT_*) — use directly 3. Variable
     * tracking — follow symbol declaration to find initializer 4. Fallback — use token value as-is
     */
    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, AstNode>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode expression,
            @Nullable IValueFactory<AstNode> valueFactory,
            int depth) {

        // Prevent infinite recursion
        if (depth > 10) {
            LOGGER.debug("[DIAG]   → resolveValues: max depth reached");
            return Collections.emptyList();
        }

        // Try CxxConstantUtils first — resolves enum values, const variables, literals
        Object constantValue = CxxConstantUtils.resolveAsConstant(expression);
        LOGGER.debug(
                "[DIAG]   resolveValues(depth={}): constantValue={} (type={}), tokenValue={}",
                depth,
                constantValue,
                constantValue != null ? constantValue.getClass().getSimpleName() : "null",
                expression.getTokenValue());
        if (constantValue != null) {
            O castValue = castValue(clazz, constantValue);
            if (castValue != null) {
                LOGGER.debug("[DIAG]   → resolved via constant: {}", castValue);
                return List.of(new ResolvedValue<>(castValue, expression));
            }
        }

        // Check if token looks like a known openHiTLS enum constant
        String tokenValue = expression.getTokenValue();
        if (tokenValue != null && isKnownEnumPrefix(tokenValue)) {
            O castValue = castValue(clazz, tokenValue);
            if (castValue != null) {
                LOGGER.debug("[DIAG]   → resolved via enum prefix: {}", castValue);
                return List.of(new ResolvedValue<>(castValue, expression));
            }
        }

        // Variable tracking: try to resolve through symbol declaration / AST walk
        if (tokenValue != null && !tokenValue.isEmpty() && isIdentifier(tokenValue)) {
            List<ResolvedValue<O, AstNode>> trackedValues =
                    resolveVariableValue(clazz, expression, valueFactory, depth);
            if (!trackedValues.isEmpty()) {
                LOGGER.debug(
                        "[DIAG]   → resolved via variable tracking: {}",
                        trackedValues.get(0).value());
                return trackedValues;
            }
        }

        // Fallback: try token value (identifiers, string literals)
        if (tokenValue != null && !tokenValue.isEmpty()) {
            // Strip quotes from string literals
            if (tokenValue.startsWith("\"") && tokenValue.endsWith("\"")) {
                tokenValue = tokenValue.substring(1, tokenValue.length() - 1);
            }
            O castValue = castValue(clazz, tokenValue);
            if (castValue != null) {
                LOGGER.debug("[DIAG]   → resolved via tokenValue: {}", castValue);
                return List.of(new ResolvedValue<>(castValue, expression));
            }
        }

        LOGGER.debug(
                "[DIAG]   → resolveValues FAILED for expression: {}", expression.getTokenValue());
        return Collections.emptyList();
    }

    /** Known openHiTLS enum constant prefixes. */
    private static final String[] ENUM_PREFIXES = {
        "CRYPT_MD_", "CRYPT_CIPHER_", "CRYPT_MAC_", "CRYPT_PKEY_",
        "CRYPT_KDF_", "CRYPT_RAND_", "CRYPT_HPKE_", "HITLS_"
    };

    /** Check if a token value looks like a known openHiTLS enum constant. */
    private boolean isKnownEnumPrefix(@Nonnull String token) {
        for (String prefix : ENUM_PREFIXES) {
            if (token.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /** Check if a token looks like a C identifier (rather than a literal, operator, etc.). */
    private boolean isIdentifier(@Nonnull String token) {
        if (token.isEmpty()) return false;
        char first = token.charAt(0);
        if (first != '_' && !Character.isLetter(first)) return false;
        // Skip common C keywords and known non-variable tokens
        return !token.equals("NULL")
                && !token.equals("true")
                && !token.equals("false")
                && !token.equals("sizeof")
                && !token.equals("void");
    }

    /**
     * Track a variable back to its declaration or most recent assignment and resolve the
     * initializer expression. Uses two strategies: 1. Symbol API (symbol.declaration()) — most
     * reliable 2. AST walk — search function body for variable declaration/assignment
     */
    @Nonnull
    private <O> List<ResolvedValue<O, AstNode>> resolveVariableValue(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode identifierNode,
            @Nullable IValueFactory<AstNode> valueFactory,
            int depth) {

        String varName = identifierNode.getTokenValue();
        LOGGER.debug(
                "[DIAG]   resolveVariableValue: varName={}, nodeType={}, nodeName={}, line={}",
                varName,
                identifierNode.getType(),
                identifierNode.getName(),
                identifierNode.getTokenLine());

        // Strategy 1: Use Symbol API if available
        // Try both the node itself and any descendant IDENTIFIER tokens
        AstNode symbolNode = identifierNode;
        // If this isn't a leaf node, find the actual IDENTIFIER descendant
        if (!identifierNode.getChildren().isEmpty()) {
            for (AstNode desc : identifierNode.getDescendants()) {
                if (varName.equals(desc.getTokenValue()) && desc.getChildren().isEmpty()) {
                    symbolNode = desc;
                    break;
                }
            }
        }

        try {
            Symbol symbol = AstNodeSymbolExtension.getSymbol(symbolNode);
            LOGGER.debug(
                    "[DIAG]   Strategy1: symbol={}, isVar={}",
                    symbol != null ? symbol.name() : "null",
                    symbol != null ? symbol.isVariableSymbol() : "N/A");
            if (symbol != null && symbol.isVariableSymbol()) {
                AstNode declaration = symbol.declaration();
                if (declaration != null) {
                    LOGGER.debug(
                            "[DIAG]   variable tracking via Symbol: {} → declaration at line {}",
                            varName,
                            declaration.getTokenLine());
                    AstNode initializer = findInitializerExpression(declaration);
                    if (initializer != null) {
                        return resolveValues(clazz, initializer, valueFactory, depth + 1);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.debug("[DIAG]   Strategy1 exception: {}", e.getMessage());
        }

        // Strategy 2: Walk the AST upward to find the enclosing function body, then
        // search for assignments/declarations of this variable name
        AstNode functionBody = findEnclosingFunctionBody(identifierNode);
        LOGGER.debug(
                "[DIAG]   Strategy2: functionBody={}, bodyName={}",
                functionBody != null ? "found" : "null",
                functionBody != null ? functionBody.getName() : "N/A");
        if (functionBody != null) {
            AstNode initValue =
                    findVariableInitInScope(functionBody, varName, identifierNode.getTokenLine());
            if (initValue != null) {
                LOGGER.debug(
                        "[DIAG]   variable tracking via AST walk: {} → init at line {}, token={}",
                        varName,
                        initValue.getTokenLine(),
                        initValue.getTokenValue());
                return resolveValues(clazz, initValue, valueFactory, depth + 1);
            } else {
                LOGGER.debug(
                        "[DIAG]   Strategy2: no init found for {} before line {}",
                        varName,
                        identifierNode.getTokenLine());
            }
        }

        return Collections.emptyList();
    }

    /**
     * Find the initializer expression from a declaration node. Looks for patterns like: Type
     * varName = INITIALIZER;
     */
    @Nullable private AstNode findInitializerExpression(@Nonnull AstNode declarationNode) {
        // Look for '=' in direct children, then take the next sibling
        boolean foundEquals = false;
        for (AstNode child : declarationNode.getChildren()) {
            if (foundEquals) {
                String childToken = child.getTokenValue();
                if (childToken != null && !childToken.equals(";") && !childToken.equals(",")) {
                    return child;
                }
            }
            if ("=".equals(child.getTokenValue())) {
                foundEquals = true;
            }
        }
        // Try looking deeper in descendants
        for (AstNode desc : declarationNode.getDescendants()) {
            if ("=".equals(desc.getTokenValue())) {
                AstNode nextSibling = desc.getNextSibling();
                if (nextSibling != null) {
                    return nextSibling;
                }
            }
        }
        return null;
    }

    /** Find the enclosing function body for a given node. */
    @Nullable private AstNode findEnclosingFunctionBody(@Nonnull AstNode node) {
        AstNode current = node.getParent();
        while (current != null) {
            String name = current.getName();
            if (name != null
                    && (name.contains("functionBody")
                            || name.contains("compoundStatement")
                            || name.contains("functionDefinition"))) {
                return current;
            }
            current = current.getParent();
        }
        return null;
    }

    /**
     * Search within a scope (function body) for the initialization/assignment of a variable.
     * Returns the value expression node for the most recent assignment before the usage line.
     *
     * <p>In C grammar, a declaration like {@code CRYPT_MD_AlgId mdId = CRYPT_MD_SHA256;} is parsed
     * as:
     *
     * <pre>
     * initDeclarator
     *   ├── declarator → declaratorId → IDENTIFIER("mdId")
     *   ├── "="
     *   └── initializerClause → ... → IDENTIFIER("CRYPT_MD_SHA256")
     * </pre>
     *
     * The IDENTIFIER is nested 2-3 levels below the node containing '=', so we must walk UP from
     * each matching identifier through ancestor nodes to find the '=' at the right level.
     */
    @Nullable private AstNode findVariableInitInScope(
            @Nonnull AstNode scope, @Nonnull String varName, int usageLine) {
        AstNode bestInit = null;
        int bestLine = -1;

        // Use manual recursive traversal — getDescendants() may not cover all levels
        List<AstNode> allNodes = new java.util.ArrayList<>();
        collectAllDescendants(scope, allNodes);
        LOGGER.debug(
                "[DIAG]   findVariableInitInScope: total descendants={}, searching for '{}' before line {}",
                allNodes.size(),
                varName,
                usageLine);

        int matchCount = 0;
        for (AstNode node : allNodes) {
            if (!varName.equals(node.getTokenValue())) {
                continue;
            }
            matchCount++;
            if (node.getTokenLine() >= usageLine) {
                LOGGER.debug(
                        "[DIAG]     found '{}' at line {} (>= usageLine {}, skipping)",
                        varName,
                        node.getTokenLine(),
                        usageLine);
                continue;
            }

            LOGGER.debug(
                    "[DIAG]     found '{}' at line {}, nodeName={}, parentName={}",
                    varName,
                    node.getTokenLine(),
                    node.getName(),
                    node.getParent() != null ? node.getParent().getName() : "null");

            // Walk UP from the identifier through ancestor nodes
            AstNode valueNode = findInitValueInAncestors(node, scope);
            if (valueNode != null && node.getTokenLine() > bestLine) {
                LOGGER.debug(
                        "[DIAG]     → found init value: token='{}', line={}",
                        valueNode.getTokenValue(),
                        valueNode.getTokenLine());
                bestInit = valueNode;
                bestLine = node.getTokenLine();
            } else if (valueNode == null) {
                LOGGER.debug("[DIAG]     → no '=' found in ancestors");
            }
        }
        LOGGER.debug(
                "[DIAG]   findVariableInitInScope: matchCount={}, bestInit={}",
                matchCount,
                bestInit != null ? bestInit.getTokenValue() : "null");

        return bestInit;
    }

    /** Recursively collect all descendant nodes into a flat list. */
    private void collectAllDescendants(@Nonnull AstNode node, @Nonnull List<AstNode> result) {
        for (AstNode child : node.getChildren()) {
            result.add(child);
            collectAllDescendants(child, result);
        }
    }

    /**
     * Walk up from an identifier node through ancestors (up to the scope boundary), looking for an
     * ancestor that contains an assignment ('='). Handles three C grammar patterns:
     *
     * <p>Pattern 1 — Direct '=' token as child (simple assignment):
     *
     * <pre>assignmentExpression { identifier, "=", value }</pre>
     *
     * <p>Pattern 2 — '=' wrapped inside braceOrEqualInitializer (declaration init):
     *
     * <pre>initDeclarator { declarator, braceOrEqualInitializer { "=", initializerClause } }</pre>
     *
     * <p>Pattern 3 — '=' wrapped inside assignmentOperator (assignment statement):
     *
     * <pre>assignmentExpression { condExpr, assignmentOperator { "=" }, initializerClause }</pre>
     */
    @Nullable private AstNode findInitValueInAncestors(
            @Nonnull AstNode identifierNode, @Nonnull AstNode scopeBoundary) {
        AstNode current = identifierNode.getParent();
        for (int level = 0; level < 5 && current != null && current != scopeBoundary; level++) {
            List<AstNode> children = current.getChildren();
            for (int i = 0; i < children.size(); i++) {
                AstNode child = children.get(i);
                String childToken = child.getTokenValue();

                if (!"=".equals(childToken)) {
                    continue;
                }
                // Make sure it's not '==' (equality comparison)
                if (i + 1 < children.size() && "=".equals(children.get(i + 1).getTokenValue())) {
                    continue;
                }

                // Case 1: child is a bare '=' token (leaf node) — value is next sibling
                if (child.getChildren().isEmpty()) {
                    if (i + 1 < children.size()) {
                        return children.get(i + 1);
                    }
                    continue;
                }

                // Case 2: wrapper node (braceOrEqualInitializer) with value INSIDE
                // Structure: braceOrEqualInitializer { "=", initializerClause }
                List<AstNode> innerChildren = child.getChildren();
                for (int j = 0; j < innerChildren.size(); j++) {
                    AstNode inner = innerChildren.get(j);
                    if ("=".equals(inner.getTokenValue()) && inner.getChildren().isEmpty()) {
                        if (j + 1 < innerChildren.size()) {
                            return innerChildren.get(j + 1);
                        }
                    }
                }
                if (innerChildren.size() >= 2) {
                    AstNode secondChild = innerChildren.get(1);
                    if (!"=".equals(secondChild.getTokenValue())) {
                        return secondChild;
                    }
                }

                // Case 3: wrapper node (assignmentOperator) with value as NEXT SIBLING
                // Structure: assignmentExpression { expr, assignmentOperator{"="}, value }
                // The wrapper only contains the operator, actual value is next sibling
                if (i + 1 < children.size()) {
                    return children.get(i + 1);
                }
            }
            current = current.getParent();
        }
        return null;
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
