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
package com.ibm.plugin.rules.detection.hitls;

import com.ibm.engine.rule.IDetectionRule;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Aggregates all openHiTLS detection rules. Combines rules for message digests, symmetric ciphers,
 * MACs, public keys, key derivation functions, and random number generators.
 */
public final class HiTLSDetectionRules {

    private HiTLSDetectionRules() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return Stream.of(
                        HiTLSMessageDigest.rules().stream(),
                        HiTLSMdOps.rules().stream(),
                        HiTLSCipher.rules().stream(),
                        HiTLSCipherOps.rules().stream(),
                        HiTLSMac.rules().stream(),
                        HiTLSMacOps.rules().stream(),
                        HiTLSPkey.rules().stream(),
                        HiTLSKdf.rules().stream(),
                        HiTLSKdfOps.rules().stream(),
                        HiTLSRand.rules().stream(),
                        HiTLSHpke.rules().stream(),
                        HiTLSTls.rules().stream(),
                        HiTLSTlsOps.rules().stream())
                .flatMap(s -> s)
                .toList();
    }
}
