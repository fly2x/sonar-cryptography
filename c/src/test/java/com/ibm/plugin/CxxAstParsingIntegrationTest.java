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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.CxxBaseDetectionRule;
import com.ibm.plugin.rules.detection.hitls.HiTLSCipher;
import com.ibm.plugin.rules.detection.hitls.HiTLSDetectionRules;
import com.ibm.plugin.rules.detection.hitls.HiTLSKdf;
import com.ibm.plugin.rules.detection.hitls.HiTLSMessageDigest;
import com.ibm.plugin.translation.reorganizer.CxxReorganizerRules;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.cxx.CxxAstScanner;
import org.sonar.cxx.squidbridge.api.SourceFile;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Integration test that verifies the full AST parsing pipeline: C source → CxxAstScanner →
 * CxxBaseDetectionRule (SquidCheck) → SourceFile.
 */
class CxxAstParsingIntegrationTest {

    /** Concrete subclass of CxxBaseDetectionRule for testing. */
    private static final class TestDetectionRule extends CxxBaseDetectionRule {
        TestDetectionRule(List<IDetectionRule<AstNode>> rules) {
            super(false, rules, CxxReorganizerRules.rules());
        }
    }

    private InputFile createInputFile(String relativePath) throws IOException {
        File file = new File(relativePath);
        String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
        return TestInputFileBuilder.create("", file.getName())
                .setProjectBaseDir(Path.of(""))
                .setContents(content)
                .setCharset(StandardCharsets.UTF_8)
                .build();
    }

    @Test
    void testScanMessageDigestFile() throws IOException {
        SquidCheck<Grammar> rule = new TestDetectionRule(HiTLSMessageDigest.rules());
        InputFile inputFile =
                createInputFile(
                        "src/test/files/rules/detection/hitls/HiTLSMessageDigestTestFile.c");
        SourceFile sourceFile = CxxAstScanner.scanSingleInputFile(inputFile, rule);
        assertThat(sourceFile).isNotNull();
        assertThat(sourceFile.getKey()).isNotNull();
    }

    @Test
    void testScanCipherFile() throws IOException {
        SquidCheck<Grammar> rule = new TestDetectionRule(HiTLSCipher.rules());
        InputFile inputFile =
                createInputFile("src/test/files/rules/detection/hitls/HiTLSCipherTestFile.c");
        SourceFile sourceFile = CxxAstScanner.scanSingleInputFile(inputFile, rule);
        assertThat(sourceFile).isNotNull();
    }

    @Test
    void testScanKdfFile() throws IOException {
        SquidCheck<Grammar> rule = new TestDetectionRule(HiTLSKdf.rules());
        InputFile inputFile =
                createInputFile("src/test/files/rules/detection/hitls/HiTLSKdfTestFile.c");
        SourceFile sourceFile = CxxAstScanner.scanSingleInputFile(inputFile, rule);
        assertThat(sourceFile).isNotNull();
    }

    @Test
    void testScanWithAllRulesLoaded() throws IOException {
        SquidCheck<Grammar> rule = new TestDetectionRule(HiTLSDetectionRules.rules());
        InputFile inputFile =
                createInputFile(
                        "src/test/files/rules/detection/hitls/HiTLSMessageDigestTestFile.c");
        SourceFile sourceFile = CxxAstScanner.scanSingleInputFile(inputFile, rule);
        assertThat(sourceFile).isNotNull();
    }
}
