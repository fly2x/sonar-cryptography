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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates C/C++ detection values in a KeyContext to mapper model nodes. Maps openHiTLS
 * CRYPT_PKEY_* enum constants to concrete algorithm classes.
 */
public final class CxxKeyContextTranslator implements IContextTranslation<AstNode> {

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
                case "CRYPT_PKEY_RSA" -> Optional.of(new RSA(detectionLocation));
                case "CRYPT_PKEY_DSA" -> Optional.of(new DSA(detectionLocation));
                case "CRYPT_PKEY_DH" -> Optional.of(new DH(detectionLocation));
                case "CRYPT_PKEY_ECDSA" -> Optional.of(new ECDSA(detectionLocation));
                case "CRYPT_PKEY_ECDH" -> Optional.of(new ECDH(detectionLocation));
                case "CRYPT_PKEY_ED25519" -> Optional.of(new Ed25519(detectionLocation));
                case "CRYPT_PKEY_X25519" -> Optional.of(new X25519(detectionLocation));
                case "CRYPT_PKEY_SM2" -> Optional.of(new SM2(detectionLocation));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
