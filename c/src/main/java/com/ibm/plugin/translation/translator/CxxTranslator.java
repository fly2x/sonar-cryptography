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
package com.ibm.plugin.translation.translator;

import com.ibm.engine.language.cxx.CxxScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.contexts.CxxCipherContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxDigestContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxKeyContextTranslator;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Dispatches to context-specific translators based on detection context type. Follows Go module's
 * GoTranslator pattern: extends ITranslator directly.
 */
public class CxxTranslator
        extends ITranslator<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> {

    public CxxTranslator() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull final IValue<AstNode> value,
            @Nonnull final IDetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), bundleIdentifier, filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        if (detectionValueContext.is(DigestContext.class)) {
            // DigestContext is also used for MAC detection (HiTLSMac uses DigestContext)
            // The CxxDigestContextTranslator handles both hash and MAC values
            final CxxDigestContextTranslator digestTranslator = new CxxDigestContextTranslator();
            return digestTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(CipherContext.class)) {
            final CxxCipherContextTranslator cipherTranslator = new CxxCipherContextTranslator();
            return cipherTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(KeyContext.class)) {
            final CxxKeyContextTranslator keyTranslator = new CxxKeyContextTranslator();
            return keyTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        return Optional.empty();
    }

    @Override
    @Nullable protected DetectionLocation getDetectionContextFrom(
            @Nonnull AstNode location, @Nonnull IBundle bundle, @Nonnull String filePath) {
        // AstNode provides line/column via getToken()
        int lineNumber = location.getTokenLine();
        int offset = location.getToken() != null ? location.getToken().getColumn() : 0;

        List<String> keywords =
                location.getTokenValue() != null ? List.of(location.getTokenValue()) : List.of();

        return new DetectionLocation(filePath, lineNumber, offset, keywords, bundle);
    }
}
