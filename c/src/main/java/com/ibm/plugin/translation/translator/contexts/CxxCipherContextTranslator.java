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
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates C/C++ detection values in a CipherContext to mapper model nodes. Maps openHiTLS
 * CRYPT_CIPHER_* enum constants to concrete algorithm classes.
 */
public final class CxxCipherContextTranslator implements IContextTranslation<AstNode> {

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
                // AES variants
                case "CRYPT_CIPHER_AES128_CBC",
                        "CRYPT_CIPHER_AES192_CBC",
                        "CRYPT_CIPHER_AES256_CBC",
                        "CRYPT_CIPHER_AES128_CTR",
                        "CRYPT_CIPHER_AES192_CTR",
                        "CRYPT_CIPHER_AES256_CTR",
                        "CRYPT_CIPHER_AES128_GCM",
                        "CRYPT_CIPHER_AES192_GCM",
                        "CRYPT_CIPHER_AES256_GCM",
                        "CRYPT_CIPHER_AES128_CCM",
                        "CRYPT_CIPHER_AES192_CCM",
                        "CRYPT_CIPHER_AES256_CCM",
                        "CRYPT_CIPHER_AES128_CFB",
                        "CRYPT_CIPHER_AES192_CFB",
                        "CRYPT_CIPHER_AES256_CFB",
                        "CRYPT_CIPHER_AES128_OFB",
                        "CRYPT_CIPHER_AES192_OFB",
                        "CRYPT_CIPHER_AES256_OFB" ->
                        Optional.of(new AES(detectionLocation));
                // SM4 variants
                case "CRYPT_CIPHER_SM4_XTS",
                        "CRYPT_CIPHER_SM4_CBC",
                        "CRYPT_CIPHER_SM4_CTR",
                        "CRYPT_CIPHER_SM4_GCM",
                        "CRYPT_CIPHER_SM4_CFB",
                        "CRYPT_CIPHER_SM4_OFB",
                        "CRYPT_CIPHER_SM4_ECB" ->
                        Optional.of(new SM4(detectionLocation));
                // ChaCha20-Poly1305
                case "CRYPT_CIPHER_CHACHA20_POLY1305" ->
                        Optional.of(new ChaCha20(detectionLocation));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
