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
package com.ibm.engine.language.cxx;

import com.ibm.engine.language.IScanContext;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.io.File;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * C/C++ scan context wrapping the sonar-cxx SquidAstVisitorContext. Accepts java.io.File (from
 * SquidAstVisitorContext) and adapts it for the IScanContext interface.
 */
public final class CxxScanContext implements IScanContext<SquidCheck<Grammar>, AstNode> {

    @Nonnull private final SquidAstVisitorContext<Grammar> visitorContext;
    @Nonnull private final File sourceFile;

    public CxxScanContext(
            @Nonnull SquidAstVisitorContext<Grammar> visitorContext, @Nonnull File sourceFile) {
        this.visitorContext = visitorContext;
        this.sourceFile = sourceFile;
    }

    @Nonnull
    public SquidAstVisitorContext<Grammar> getVisitorContext() {
        return visitorContext;
    }

    @Override
    public void reportIssue(
            @Nonnull SquidCheck<Grammar> currentRule,
            @Nonnull AstNode tree,
            @Nonnull String message) {
        visitorContext.createLineViolation(currentRule, message, tree);
    }

    @Nonnull
    @Override
    public InputFile getInputFile() {
        // sonar-cxx SquidAstVisitorContext provides java.io.File, not InputFile.
        // This wraps it for compatibility. In production this will be used via
        // SensorContext which has proper InputFile resolution.
        throw new UnsupportedOperationException(
                "CxxScanContext does not have InputFile; use getFilePath() instead");
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return sourceFile.getAbsolutePath();
    }
}
