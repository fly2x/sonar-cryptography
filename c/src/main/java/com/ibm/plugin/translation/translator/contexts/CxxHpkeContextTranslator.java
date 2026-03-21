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
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates openHiTLS HPKE (Hybrid Public Key Encryption) values to model nodes.
 *
 * <p>HPKE (RFC 9180) composes three primitives:
 *
 * <ul>
 *   <li>KEM — Key Encapsulation Mechanism (e.g. DHKEM-X25519, DHKEM-P256)
 *   <li>KDF — Key Derivation Function (e.g. HKDF-SHA256)
 *   <li>AEAD — Authenticated Encryption with Associated Data (e.g. AES-128-GCM)
 * </ul>
 *
 * <p>The openHiTLS API groups these into a {@code CRYPT_HPKE_CipherSuite} structure. This
 * translator also handles the individual HPKE sub-function APIs:
 *
 * <ul>
 *   <li>CRYPT_EAL_HpkeSetupBaseS — sender setup
 *   <li>CRYPT_EAL_HpkeSetupBaseR — receiver setup
 *   <li>CRYPT_EAL_HpkeSeal — encrypt+encapsulate
 *   <li>CRYPT_EAL_HpkeOpen — decrypt+decapsulate
 * </ul>
 */
public final class CxxHpkeContextTranslator implements IContextTranslation<AstNode> {

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
                case "HPKE" -> {
                    // HPKE as a composite scheme: KEM + KDF + AEAD
                    Algorithm hpke =
                            new Algorithm("HPKE", PublicKeyEncryption.class, detectionLocation);
                    // Add KEM child (default: DHKEM-X25519 per RFC 9180)
                    hpke.put(
                            new Algorithm(
                                    "DHKEM", KeyEncapsulationMechanism.class, detectionLocation));
                    // Add KDF child (default: HKDF-SHA256)
                    hpke.put(
                            new Algorithm(
                                    "HKDF-SHA256", KeyDerivationFunction.class, detectionLocation));
                    yield Optional.of(hpke);
                }
                case "SEAL" -> {
                    // HPKE seal = encrypt + encapsulate
                    Algorithm seal =
                            new Algorithm(
                                    "HPKE-Seal", PublicKeyEncryption.class, detectionLocation);
                    yield Optional.of(seal);
                }
                case "OPEN" -> {
                    // HPKE open = decrypt + decapsulate
                    Algorithm open =
                            new Algorithm(
                                    "HPKE-Open", PublicKeyEncryption.class, detectionLocation);
                    yield Optional.of(open);
                }
                case "SETUP_BASE_S" -> {
                    Algorithm setup =
                            new Algorithm(
                                    "HPKE-SetupBaseS",
                                    PublicKeyEncryption.class,
                                    detectionLocation);
                    yield Optional.of(setup);
                }
                case "SETUP_BASE_R" -> {
                    Algorithm setup =
                            new Algorithm(
                                    "HPKE-SetupBaseR",
                                    PublicKeyEncryption.class,
                                    detectionLocation);
                    yield Optional.of(setup);
                }
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
