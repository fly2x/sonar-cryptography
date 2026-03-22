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

import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import java.util.stream.StreamSupport;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.cxx.CxxAstScanner;
import org.sonar.cxx.squidbridge.SquidAstVisitor;

/**
 * Custom SonarQube sensor for C/C++ cryptographic detection. Uses sonar-cxx's CxxAstScanner to
 * parse C/C++ files and run CxxBaseDetectionRule checks (SquidCheck visitors) against the AST.
 */
public class CryptoCxxSensor implements Sensor {

    private static final Logger LOG = LoggerFactory.getLogger(CryptoCxxSensor.class);

    @Override
    public void describe(@Nonnull SensorDescriptor descriptor) {
        descriptor.onlyOnLanguage("cxx").name("Cryptography for C/C++");
    }

    @Override
    public void execute(@Nonnull SensorContext context) {
        FileSystem fs = context.fileSystem();
        List<InputFile> inputFiles =
                StreamSupport.stream(
                                fs.inputFiles(
                                                fs.predicates()
                                                        .and(
                                                                fs.predicates().hasLanguage("cxx"),
                                                                fs.predicates()
                                                                        .hasType(
                                                                                InputFile.Type
                                                                                        .MAIN)))
                                        .spliterator(),
                                false)
                        .toList();

        if (inputFiles.isEmpty()) {
            LOG.info("No C/C++ files found for cryptographic analysis");
            return;
        }

        LOG.info("Cryptography C/C++ analysis: {} files", inputFiles.size());

        // Create our detection rules as SquidCheck visitors
        @SuppressWarnings("unchecked")
        SquidAstVisitor<Grammar>[] visitors =
                CxxRuleList.getCxxChecks().stream()
                        .map(
                                checkClass -> {
                                    try {
                                        return checkClass.getDeclaredConstructor().newInstance();
                                    } catch (Exception e) {
                                        LOG.error(
                                                "Failed to instantiate check: {}",
                                                checkClass.getName(),
                                                e);
                                        return null;
                                    }
                                })
                        .filter(java.util.Objects::nonNull)
                        .toArray(SquidAstVisitor[]::new);

        if (visitors.length == 0) {
            LOG.warn("No C/C++ checks configured");
            return;
        }

        // Process each file using sonar-cxx's AST scanner
        for (InputFile inputFile : inputFiles) {
            if (context.isCancelled()) {
                break;
            }
            try {
                CxxAstScanner.scanSingleInputFile(inputFile, visitors);
                LOG.debug("Analyzed: {}", inputFile.uri());
            } catch (Exception e) {
                LOG.warn("Error analyzing {}: {}", inputFile.uri(), e.getMessage());
            }
        }

        LOG.info("Cryptography C/C++ analysis complete");
    }
}
