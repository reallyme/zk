// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask

plugins {
    id("com.android.application")
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
}

val detektCli =
    configurations.create("detektCli") {
        isCanBeConsumed = false
        isCanBeResolved = true
    }
val detektConfigFile = layout.projectDirectory.file("detekt.yml")
val generatedDemoAssetsDir = layout.buildDirectory.dir("generated/reallyme-zk-demo-assets")
val generatedDemoAssetsFile = generatedDemoAssetsDir.get().asFile
val stagedZkDemoAssetsDir = generatedDemoAssetsDir.map { it.dir("zk_demo") }
val generatedClaimBundle4DiagnosticAssetsDir =
    layout.buildDirectory.dir("generated/reallyme-zk-claim-bundle4-diagnostic-assets")
val generatedClaimBundle4DiagnosticAssetsFile = generatedClaimBundle4DiagnosticAssetsDir.get().asFile
val demoFixtureDir = rootProject.layout.projectDirectory.dir("../../vectors/demo-flow-inputs/v1")
val mobileDemoArtifactsDir =
    rootProject.layout.projectDirectory.dir(
        "../../build/native/mobile-demo-artifacts-persona-credential-evidence-v1-candidate",
    )
val commonCredentialRootMobileFixturesDir =
    rootProject.layout.projectDirectory.dir(
        "../../vectors/common-credential-root-mobile-fixtures-v1",
    )
val commonCredentialRootStageRequestsDir =
    rootProject.layout.projectDirectory.dir(
        "../../vectors/common-credential-root-stage-requests-v1",
    )
val commonCredentialRootStageRequestManifest =
    rootProject.layout.projectDirectory.file(
        "../../vectors/common-credential-root-stage-requests-v1.sha256.tsv",
    )
val personaCredentialEvidenceMobileRequestsDir =
    rootProject.layout.projectDirectory.dir(
        "../../vectors/persona-credential-evidence-mobile-requests-v1",
    )
val commonCredentialRootSourceLock =
    rootProject.layout.projectDirectory.file("../../circuits/modern-circuit-source-lock.tsv")
val stageDemoAssetsScript = rootProject.layout.projectDirectory.file("../../scripts/stage-demo-mobile-assets.mjs")
val stageClaimBundle4DiagnosticAssetsScript =
    rootProject.layout.projectDirectory.file("../../scripts/stage-android-claim-bundle4-diagnostic-assets.sh")
val claimBundle4DiagnosticTestSelector =
    "me.really.zk.demo.android.ReallyMeZKDemoInstrumentationTest#" +
        "largestClaimBundle4DiagnosticProveVerifyRecordsPeakMemoryOnDevice"
val claimBundle4DiagnosticEnabled =
    providers
        .gradleProperty("reallymeZkClaimBundle4Diagnostic")
        .map { it == "true" }
        .orElse(false)
val crsRootProvider =
    providers
        .environmentVariable("REALLYME_ZK_DEMO_CRS_DIR")
        .orElse("${System.getProperty("user.home")}/.bb-crs")
val crsG1FileProvider = crsRootProvider.map { File(it, "bn254_g1.dat") }
val crsG2FileProvider = crsRootProvider.map { File(it, "bn254_g2.dat") }
val expectedReleaseIndexSha256 = "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7"
val expectedG1PrefixSha256 = "0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5"
val expectedG2Sha256 = "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f"
val proverG1PrefixBytes = 67_108_928
val g2Bytes = 128

val stageZkDemoAssets =
    tasks.register<Exec>("stageZkDemoAssets") {
        inputs.file(stageDemoAssetsScript)
        inputs.property("mobileDemoArtifactsDirPath", mobileDemoArtifactsDir.asFile.absolutePath)
        inputs.property(
            "commonCredentialRootMobileFixturesDirPath",
            commonCredentialRootMobileFixturesDir.asFile.absolutePath,
        )
        inputs.property(
            "commonCredentialRootStageRequestsDirPath",
            commonCredentialRootStageRequestsDir.asFile.absolutePath,
        )
        inputs.property(
            "commonCredentialRootStageRequestManifestPath",
            commonCredentialRootStageRequestManifest.asFile.absolutePath,
        )
        inputs.dir(personaCredentialEvidenceMobileRequestsDir)
        inputs.file(commonCredentialRootSourceLock)
        for (lane in listOf("sha256", "poseidon2")) {
            val stagePrograms =
                listOf(
                    Triple(
                        "root_attestation",
                        "credential_common_credential_root_v1_attestation_$lane",
                        "attestation-proof",
                    ),
                    Triple("root_status", "credential_common_credential_root_v1_status_$lane", "status-proof"),
                    Triple("lineage", "credential_common_credential_root_v1_lineage_$lane", "lineage-proof"),
                    Triple("private_persona_claim", "common_credential_root_v1_${lane}_private_persona_claim", "proof"),
                    Triple("public_persona_claim", "common_credential_root_v1_${lane}_public_persona_claim", "proof"),
                )
            for ((stage, program, proofDirectory) in stagePrograms) {
                val target = "../../circuits/$lane/families/common_credential_root_v1/$stage/target"
                inputs.property(
                    "commonCredentialRootProgramPath-$lane-$stage",
                    rootProject
                        .layout
                        .projectDirectory
                        .file("$target/$program.json")
                        .asFile
                        .absolutePath,
                )
                inputs.property(
                    "commonCredentialRootVerificationKeyPath-$lane-$stage",
                    rootProject
                        .layout
                        .projectDirectory
                        .file("$target/$proofDirectory/vk")
                        .asFile
                        .absolutePath,
                )
            }
        }
        inputs.property("crsG1Path", crsG1FileProvider.map { it.absolutePath })
        inputs.property("crsG2Path", crsG2FileProvider.map { it.absolutePath })
        inputs.property("expectedReleaseIndexSha256", expectedReleaseIndexSha256)
        inputs.property("expectedG1PrefixSha256", expectedG1PrefixSha256)
        inputs.property("expectedG2Sha256", expectedG2Sha256)
        inputs.property("proverG1PrefixBytes", proverG1PrefixBytes)
        inputs.property("g2Bytes", g2Bytes)
        commandLine(
            "node",
            stageDemoAssetsScript.asFile.absolutePath,
            stagedZkDemoAssetsDir.get().asFile.absolutePath,
        )
        outputs.dir(stagedZkDemoAssetsDir)
    }

val stageDemoFlowInputs =
    tasks.register<Sync>("stageDemoFlowInputs") {
        from(demoFixtureDir) {
            include("*.pb")
            include("SHA256SUMS")
        }
        into(generatedDemoAssetsDir.map { it.dir("flow_inputs") })
        doLast {
            val stagedRoot = generatedDemoAssetsDir.get().dir("flow_inputs").asFile
            val stagedFiles =
                stagedRoot
                    .walkTopDown()
                    .filter { it.isFile }
                    .map { it.relativeTo(stagedRoot).invariantSeparatorsPath }
                    .sorted()
                    .toList()
            val expectedFiles =
                demoFixtureDir
                    .asFile
                    .listFiles { file -> file.isFile && (file.extension == "pb" || file.name == "SHA256SUMS") }
                    ?.map { it.name }
                    ?.sorted()
                    ?: emptyList()
            check(stagedFiles == expectedFiles) {
                "Android demo flow input staging contains unexpected files"
            }
        }
    }

val stageClaimBundle4DiagnosticAssets =
    tasks.register<Exec>("stageClaimBundle4DiagnosticAssets") {
        inputs.file(stageClaimBundle4DiagnosticAssetsScript)
        inputs.dir(rootProject.layout.projectDirectory.dir("../../circuits"))
        outputs.dir(generatedClaimBundle4DiagnosticAssetsDir)
        onlyIf { claimBundle4DiagnosticEnabled.get() }
        commandLine(
            stageClaimBundle4DiagnosticAssetsScript.asFile.absolutePath,
            generatedClaimBundle4DiagnosticAssetsFile.absolutePath,
        )
    }

android {
    namespace = "me.really.zk.demo.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "me.really.zk.demo.android"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.3.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        if (claimBundle4DiagnosticEnabled.get()) {
            testInstrumentationRunnerArguments["reallymeZkClaimBundle4Diagnostic"] = "true"
        } else {
            testInstrumentationRunnerArguments["notClass"] = claimBundle4DiagnosticTestSelector
        }
    }

    sourceSets {
        getByName("main") {
            assets.directories.add(generatedDemoAssetsFile.absolutePath)
        }
        getByName("androidTest") {
            assets.directories.add(generatedClaimBundle4DiagnosticAssetsFile.absolutePath)
        }
    }
}

dependencies {
    implementation(project(":android-native"))
    implementation(project(":demo-shared"))
    detektCli("io.gitlab.arturbosch.detekt:detekt-cli:1.23.8")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    testImplementation(kotlin("test-junit"))
}

ktlint {
    additionalEditorconfig.set(
        mapOf("ktlint_standard_property-naming" to "disabled"),
    )
}

tasks.register<JavaExec>("detekt") {
    group = "verification"
    description = "Runs detekt analysis without the deprecated Gradle plugin APIs."
    classpath = detektCli
    mainClass.set("io.gitlab.arturbosch.detekt.cli.Main")
    args(
        "--input",
        files("src/main/kotlin", "src/test/kotlin", "src/androidTest/kotlin")
            .filter { it.exists() }
            .joinToString(",") { it.absolutePath },
        "--config",
        detektConfigFile.asFile.absolutePath,
        "--build-upon-default-config",
    )
}

tasks.withType<KotlinCompilationTask<*>>().configureEach {
    compilerOptions {
        allWarningsAsErrors.set(true)
        freeCompilerArgs.add("-Xexplicit-api=strict")
    }
}

tasks.named("check") {
    dependsOn("ktlintCheck", "detekt", "testDebugUnitTest", "assembleDebug", "assembleDebugAndroidTest")
}

tasks.named("preBuild") {
    dependsOn(stageZkDemoAssets, stageDemoFlowInputs)
    dependsOn(stageClaimBundle4DiagnosticAssets)
}
