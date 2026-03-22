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
package com.ibm.plugin.rules;

import com.ibm.engine.detection.Finding;
import com.ibm.engine.language.cxx.CxxScanContext;
import com.ibm.mapper.model.INode;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import java.util.function.Consumer;
import javax.annotation.Nonnull;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Detection collection rule for cbomkit-lib integration. Extends {@link CxxInventoryRule} and
 * forwards translated nodes to a consumer callback, allowing the cbomkit scanning pipeline to
 * collect CBOM findings.
 */
public class CxxDetectionCollectionRule extends CxxInventoryRule {
    private final Consumer<List<INode>> handler;

    public CxxDetectionCollectionRule(@Nonnull Consumer<List<INode>> findingConsumer) {
        this.handler = findingConsumer;
    }

    @Override
    public void update(
            @Nonnull Finding<SquidCheck<Grammar>, AstNode, Symbol, CxxScanContext> finding) {
        super.update(finding);
        final List<INode> nodes = cxxTranslationProcess.initiate(finding.detectionStore());
        handler.accept(nodes);
    }
}
