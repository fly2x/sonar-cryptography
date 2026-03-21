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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates C/C++ PRNG detection values to mapper model nodes. Maps openHiTLS CRYPT_RAND_* enum
 * constants to Algorithm nodes tagged as PseudorandomNumberGenerator (following Go module pattern).
 */
public final class CxxPRNGContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>) {
            String val = value.asString();
            if (val == null || val.isEmpty()) {
                return Optional.empty();
            }
            String upper = val.toUpperCase().trim();
            if (upper.startsWith("CRYPT_RAND_")) {
                // Extract the algorithm name from the enum, e.g.
                // CRYPT_RAND_SHA256 → SHA256-DRBG
                String algoName = upper.substring("CRYPT_RAND_".length()) + "-DRBG";
                return Optional.of(
                        new Algorithm(
                                algoName, PseudorandomNumberGenerator.class, detectionLocation));
            }
        }

        return Optional.empty();
    }
}
