// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.protocodec

import reallyme.zk.v1.Manifest
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class ZkCanonicalFixtureTest {
    @Test
    fun commonRootRequestsRetainTheNativeCanonicalEncoding() {
        val root = repositoryRoot()
        for (directory in listOf(
            "vectors/common-credential-root-mobile-fixtures-v1",
            "vectors/common-credential-root-stage-requests-v1",
        )) {
            Files.list(root.resolve(directory)).use { entries ->
                val fixtures = entries.filter { it.fileName.toString().endsWith(".pb") }.toList()
                assertTrue(fixtures.isNotEmpty())
                fixtures.forEach(::assertCanonicalFixture)
            }
        }
    }

    private fun assertCanonicalFixture(fixture: Path) {
        val bytes = Files.readAllBytes(fixture)
        val encoded = Manifest.ZkProviderOperationRequest.parseFrom(bytes).toByteArray()
        try {
            assertContentEquals(bytes, encoded, "Canonical field order differs: ${fixture.fileName}")
        } finally {
            bytes.fill(0)
            encoded.fill(0)
        }
    }

    private fun repositoryRoot(): Path =
        requireNotNull(
            generateSequence(Path.of("").toAbsolutePath()) { it.parent }
                .firstOrNull { Files.isDirectory(it.resolve("vectors/common-credential-root-stage-requests-v1")) },
        )
}
