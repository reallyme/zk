// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import org.gradle.api.publish.maven.MavenPublication

plugins {
    kotlin("jvm")
    id("maven-publish")
    `java-library`
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        allWarningsAsErrors = true
    }
}

sourceSets {
    named("main") {
        java.srcDir("../../../gen/java/zk")
        kotlin.srcDir("../../../gen/kotlin/zk")
    }
}

dependencies {
    api("com.google.protobuf:protobuf-javalite:4.36.2")
    api("com.google.protobuf:protobuf-kotlin-lite:4.36.2")
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
            artifactId = "zk-proto-generated"
            pom {
                name.set("ReallyMe ZK Kotlin Protobuf Models")
                description.set("Generated Kotlin and Java protobuf models for ReallyMe zero-knowledge provider contracts.")
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
