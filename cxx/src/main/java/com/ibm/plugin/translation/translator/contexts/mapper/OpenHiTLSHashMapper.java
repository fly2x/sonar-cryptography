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
package com.ibm.plugin.translation.translator.contexts.mapper;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Maps openHiTLS hash algorithm identifiers (enum constants and function names) to standard
 * algorithm model classes for CBOM.
 */
public final class OpenHiTLSHashMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nonnull String str, @Nonnull DetectionLocation detectionLocation) {
        return switch (str) {
            case "CRYPT_MD_MD5" -> Optional.of(new MD5(detectionLocation));
            case "CRYPT_MD_SHA1" -> Optional.of(new SHA(detectionLocation));
            case "CRYPT_MD_SHA224" -> Optional.of(new SHA2(224, detectionLocation));
            case "CRYPT_MD_SHA256" -> Optional.of(new SHA2(256, detectionLocation));
            case "CRYPT_MD_SHA384" -> Optional.of(new SHA2(384, detectionLocation));
            case "CRYPT_MD_SHA512" -> Optional.of(new SHA2(512, detectionLocation));
            case "CRYPT_MD_SHA3_224" -> Optional.of(new SHA3(224, detectionLocation));
            case "CRYPT_MD_SHA3_256" -> Optional.of(new SHA3(256, detectionLocation));
            case "CRYPT_MD_SHA3_384" -> Optional.of(new SHA3(384, detectionLocation));
            case "CRYPT_MD_SHA3_512" -> Optional.of(new SHA3(512, detectionLocation));
            case "CRYPT_MD_SM3" -> Optional.of(new SM3(detectionLocation));
            default -> Optional.empty();
        };
    }
}
