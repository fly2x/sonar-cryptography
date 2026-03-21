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
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates C/C++ KeyAgreement detection values to model nodes. Maps CRYPT_PKEY_DH/ECDH to
 * KeyAgreement nodes (DH, ECDH).
 */
public final class CxxKeyAgreementContextTranslator implements IContextTranslation<AstNode> {

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
            return switch (val.toUpperCase().trim()) {
                case "CRYPT_PKEY_DH" ->
                        Optional.of(new Algorithm("DH", KeyAgreement.class, detectionLocation));
                case "CRYPT_PKEY_ECDH" ->
                        Optional.of(new Algorithm("ECDH", KeyAgreement.class, detectionLocation));
                case "CRYPT_PKEY_X25519" ->
                        Optional.of(new Algorithm("X25519", KeyAgreement.class, detectionLocation));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
