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

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates C/C++ detection values in a DigestContext to mapper model nodes. Maps openHiTLS enum
 * constants (CRYPT_MD_* and CRYPT_MAC_*) to concrete algorithm model classes.
 *
 * <p>Note: HiTLSMac detection rules also use DigestContext, so MAC values (CRYPT_MAC_*) are handled
 * here alongside digest values (CRYPT_MD_*).
 */
public final class CxxDigestContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode> || value instanceof Algorithm<AstNode>) {
            String val = value.asString();
            if (val == null || val.isEmpty()) {
                return Optional.empty();
            }
            return switch (val.toUpperCase().trim()) {
                // Message Digest algorithms (CRYPT_MD_*)
                case "MD5", "CRYPT_MD_MD5" -> Optional.of(new MD5(detectionLocation));
                case "SHA1", "SHA-1", "CRYPT_MD_SHA1" -> Optional.of(new SHA(detectionLocation));
                case "SHA224", "SHA-224", "CRYPT_MD_SHA224" ->
                        Optional.of(new SHA2(224, detectionLocation));
                case "SHA256", "SHA-256", "CRYPT_MD_SHA256" ->
                        Optional.of(new SHA2(256, detectionLocation));
                case "SHA384", "SHA-384", "CRYPT_MD_SHA384" ->
                        Optional.of(new SHA2(384, detectionLocation));
                case "SHA512", "SHA-512", "CRYPT_MD_SHA512" ->
                        Optional.of(new SHA2(512, detectionLocation));
                case "SHA3-224", "CRYPT_MD_SHA3_224" ->
                        Optional.of(new SHA3(224, detectionLocation));
                case "SHA3-256", "CRYPT_MD_SHA3_256" ->
                        Optional.of(new SHA3(256, detectionLocation));
                case "SHA3-384", "CRYPT_MD_SHA3_384" ->
                        Optional.of(new SHA3(384, detectionLocation));
                case "SHA3-512", "CRYPT_MD_SHA3_512" ->
                        Optional.of(new SHA3(512, detectionLocation));
                case "SM3", "CRYPT_MD_SM3" -> Optional.of(new SM3(detectionLocation));

                // MAC algorithms (CRYPT_MAC_*) — also routed through DigestContext
                case "CRYPT_MAC_HMAC_MD5" -> Optional.of(new HMAC(new MD5(detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA1" -> Optional.of(new HMAC(new SHA(detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA224" ->
                        Optional.of(new HMAC(new SHA2(224, detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA256" ->
                        Optional.of(new HMAC(new SHA2(256, detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA384" ->
                        Optional.of(new HMAC(new SHA2(384, detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA512" ->
                        Optional.of(new HMAC(new SHA2(512, detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA3_224" ->
                        Optional.of(new HMAC(new SHA3(224, detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA3_256" ->
                        Optional.of(new HMAC(new SHA3(256, detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA3_384" ->
                        Optional.of(new HMAC(new SHA3(384, detectionLocation)));
                case "CRYPT_MAC_HMAC_SHA3_512" ->
                        Optional.of(new HMAC(new SHA3(512, detectionLocation)));
                case "CRYPT_MAC_HMAC_SM3" -> Optional.of(new HMAC(new SM3(detectionLocation)));
                case "CRYPT_MAC_CMAC_AES128", "CRYPT_MAC_CMAC_AES256" ->
                        Optional.of(new CMAC(detectionLocation));

                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
