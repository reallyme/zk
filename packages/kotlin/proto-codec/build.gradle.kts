// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import org.gradle.api.publish.maven.MavenPublication

plugins {
    kotlin("jvm")
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
    id("maven-publish")
    `java-library`
}

val detektCli =
    configurations.create("detektCli") {
        isCanBeConsumed = false
        isCanBeResolved = true
    }

kotlin {
    explicitApi()
    jvmToolchain(17)
    compilerOptions {
        allWarningsAsErrors = true
    }
}

dependencies {
    api(project(":proto-generated"))
    detektCli("io.gitlab.arturbosch.detekt:detekt-cli:1.23.8")
    testImplementation(kotlin("test"))
}

publishing {
    repositories {
        maven {
            name = "localReleaseArtifacts"
            url =
                uri(
                    rootProject.layout.projectDirectory
                        .dir("../../build/maven/repository")
                        .asFile,
                )
        }
    }
    publications {
        create<MavenPublication>("release") {
            from(components["java"])
            artifactId = "zk-proto-codec"
            pom {
                name.set("ReallyMe ZK Kotlin Protobuf Codec")
                description.set("Kotlin protobuf codec helpers for ReallyMe zero-knowledge provider contracts.")
                if (!providers.gradleProperty("reallymeZkCentralStaging").isPresent) {
                    licenses {
                        license {
                            name.set("MIT OR Apache-2.0")
                        }
                    }
                }
            }
        }
    }
}

tasks.register<JavaExec>("detekt") {
    group = "verification"
    description = "Runs detekt analysis without the deprecated Gradle plugin APIs."
    classpath = detektCli
    mainClass.set("io.gitlab.arturbosch.detekt.cli.Main")
    args(
        "--input",
        files("src/main/kotlin", "src/test/kotlin")
            .filter { it.exists() }
            .joinToString(",") { it.absolutePath },
        "--build-upon-default-config",
    )
}

tasks.named("check") {
    dependsOn("ktlintCheck", "detekt", "test")
}
