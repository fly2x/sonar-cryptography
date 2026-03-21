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
package com.ibm.plugin.rules.detection;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.hitls.HiTLSDetectionRules;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Central registry of all C/C++ cryptographic detection rules. Aggregates detection rules from all
 * supported cryptographic libraries.
 */
public final class CxxDetectionRules {

    private CxxDetectionRules() {}

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        List<IDetectionRule<AstNode>> rules = new ArrayList<>();
        // openHiTLS rules
        rules.addAll(HiTLSDetectionRules.rules());
        // mbedTLS rules (Phase 3)
        // OpenSSL rules (Phase 4)
        return rules;
    }
}
