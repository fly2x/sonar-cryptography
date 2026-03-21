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

import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.language.ILanguageTranslation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * Language translation implementation for C/C++. Extracts method names, parameter types, and
 * identifiers from sonar-cxx AstNode.
 *
 * <p>C has no classes or namespaces (in pure C), so: - getInvokedObjectTypeString always returns
 * empty (C global functions) - getMethodName extracts the function name from the call expression -
 * resolveIdentifierAsString extracts identifier or literal text
 */
public final class CxxLanguageTranslation implements ILanguageTranslation<AstNode> {

    @Nonnull
    private static final Logger LOGGER = LoggerFactory.getLogger(CxxLanguageTranslation.class);

    @Nonnull
    @Override
    public Optional<String> getMethodName(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        // Use CxxAstNodeHelper to extract function call name
        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            String name = CxxAstNodeHelper.getFunctionCallName(methodInvocation);
            if (name != null && !name.isEmpty()) {
                return Optional.of(name);
            }
        }
        // Fallback: try to get token value
        if (methodInvocation.getTokenValue() != null) {
            return Optional.of(methodInvocation.getTokenValue());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<IType> getInvokedObjectTypeString(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        // C global functions have no invoking object type.
        // For C++ methods (e.g., obj.method()), this could be extended.
        // Return a type that matches empty string (standard for C global functions).
        return Optional.of(expectedType -> expectedType.isEmpty() || "".equals(expectedType));
    }

    @Nonnull
    @Override
    public Optional<IType> getMethodReturnTypeString(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        // sonar-cxx does not easily expose return types at the AST level
        return Optional.empty();
    }

    @Nonnull
    @Override
    public List<IType> getMethodParameterTypes(
            @Nonnull MatchContext matchContext, @Nonnull AstNode methodInvocation) {
        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            List<AstNode> args = CxxAstNodeHelper.getFunctionCallArguments(methodInvocation);
            if (args == null || args.isEmpty()) {
                return Collections.emptyList();
            }
            List<IType> types = new ArrayList<>();
            for (int i = 0; i < args.size(); i++) {
                // C parameters are loosely typed in AST; match any type
                types.add(expectedType -> true);
            }
            return types;
        }
        return Collections.emptyList();
    }

    @Nonnull
    @Override
    public Optional<String> resolveIdentifierAsString(
            @Nonnull MatchContext matchContext, @Nonnull AstNode identifier) {
        if (identifier == null) {
            return Optional.empty();
        }
        // Try to resolve as a constant value (enum, const, literal)
        Object constantValue = org.sonar.cxx.utils.CxxConstantUtils.resolveAsConstant(identifier);
        if (constantValue != null) {
            return Optional.of(constantValue.toString());
        }
        // Fallback: get token value
        String tokenValue = identifier.getTokenValue();
        if (tokenValue != null && !tokenValue.isEmpty()) {
            return Optional.of(tokenValue);
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumIdentifierName(
            @Nonnull MatchContext matchContext, @Nonnull AstNode enumIdentifier) {
        if (enumIdentifier == null) {
            return Optional.empty();
        }
        // Try constant resolution first (handles enum constants)
        Object constantValue =
                org.sonar.cxx.utils.CxxConstantUtils.resolveAsConstant(enumIdentifier);
        if (constantValue != null) {
            return Optional.of(constantValue.toString());
        }
        // Fallback to token value
        String tokenValue = enumIdentifier.getTokenValue();
        if (tokenValue != null) {
            return Optional.of(tokenValue);
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<String> getEnumClassName(
            @Nonnull MatchContext matchContext, @Nonnull AstNode enumClass) {
        // C does not have enum classes (C++ has enum class, but not typical in crypto APIs)
        return Optional.empty();
    }
}
