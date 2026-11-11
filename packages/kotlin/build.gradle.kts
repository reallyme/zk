import org.gradle.api.GradleException
import org.gradle.api.artifacts.component.ComponentIdentifier
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.artifacts.result.UnresolvedArtifactResult
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.jvm.JvmLibrary
import org.gradle.language.base.artifact.SourcesArtifact

// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

plugins {
    kotlin("jvm") version "2.4.21"
    id("com.android.application") version "9.5.1" apply false
    id("com.android.library") version "9.5.1" apply false
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
    id("maven-publish")
    `java-library`
}

group = "me.really"
version = "0.3.1"

if (providers.gradleProperty("reallymeZkCentralStaging").isPresent) {
    apply(from = "gradle/central-publication.gradle.kts")
}

allprojects {
    group = rootProject.group
    version = rootProject.version
    dependencyLocking {
        lockAllConfigurations()
    }
}

val detektCli =
    configurations.create("detektCli") {
        isCanBeConsumed = false
        isCanBeResolved = true
    }
val detektConfigFile = layout.projectDirectory.file("detekt.yml")

kotlin {
    explicitApi()
    jvmToolchain(17)
    compilerOptions {
        allWarningsAsErrors = true
    }
}

dependencies {
    api(project(":proto-codec"))
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
            artifactId = "zk"
            pom {
                name.set("ReallyMe ZK Kotlin Provider")
                description.set("Kotlin provider APIs for ReallyMe zero-knowledge proof operations.")
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

tasks.register("publishKotlinProviderPublicationsToLocalReleaseArtifactsRepository") {
    group = "publishing"
    description =
        "Publishes the ZK Kotlin provider modules and Android native AAR into the local build/maven repository."
    dependsOn(
        ":proto-generated:publishReleasePublicationToLocalReleaseArtifactsRepository",
        ":proto-codec:publishReleasePublicationToLocalReleaseArtifactsRepository",
        ":publishReleasePublicationToLocalReleaseArtifactsRepository",
        ":android-native:publishReleasePublicationToLocalReleaseArtifactsRepository",
        ":android-native:verifyPublishedAndroidAarNativeLibraries",
    )
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
        "--config",
        detektConfigFile.asFile.absolutePath,
        "--build-upon-default-config",
    )
}

tasks.register("resolveIdeDependencySources") {
    group = "verification"
    description = "Resolves IDE source artifacts so strict dependency verification covers Android Studio model import."
    doLast {
        val componentIds = linkedSetOf<ComponentIdentifier>()
        allprojects.forEach { inspectedProject ->
            inspectedProject.configurations
                .filter { configuration -> configuration.isCanBeResolved }
                .forEach { configuration ->
                    try {
                        configuration.incoming.resolutionResult.allComponents.forEach { component ->
                            componentIds.add(component.id)
                        }
                    } catch (error: RuntimeException) {
                        throw GradleException(
                            "failed to resolve ${inspectedProject.path}:${configuration.name} while collecting IDE source artifacts",
                            error,
                        )
                    }
                }
        }

        val externalComponentIds = componentIds.filterNot { componentId -> componentId is ProjectComponentIdentifier }
        val artifactResults =
            dependencies
                .createArtifactResolutionQuery()
                .forComponents(externalComponentIds)
                .withArtifacts(JvmLibrary::class.java, SourcesArtifact::class.java)
                .execute()

        val unresolvedSources =
            artifactResults
                .resolvedComponents
                .flatMap { component ->
                    component
                        .getArtifacts(SourcesArtifact::class.java)
                        .filterIsInstance<UnresolvedArtifactResult>()
                        .map { artifact -> "${component.id.displayName}: ${artifact.failure.message}" }
                }

        if (unresolvedSources.isNotEmpty()) {
            throw GradleException(
                unresolvedSources.joinToString(
                    separator = System.lineSeparator(),
                    prefix = "failed to resolve IDE source artifacts:${System.lineSeparator()}",
                ),
            )
        }

        val sourceDependencyNotations =
            artifactResults
                .resolvedComponents
                .flatMap { component ->
                    component
                        .getArtifacts(SourcesArtifact::class.java)
                        .filterIsInstance<ResolvedArtifactResult>()
                }.mapNotNull { artifact ->
                    val module = artifact.id.componentIdentifier as? ModuleComponentIdentifier
                    if (module == null) {
                        null
                    } else {
                        ideArtifactDependencyNotations(module, artifact.file.name)
                    }
                }.flatten()
                .toSortedSet()

        if (sourceDependencyNotations.isNotEmpty()) {
            val sourceDependencies =
                sourceDependencyNotations
                    .map { notation -> dependencies.create(notation) }
                    .toTypedArray()
            val sourceVerificationConfiguration = configurations.detachedConfiguration(*sourceDependencies)
            sourceVerificationConfiguration.isTransitive = false
            try {
                sourceVerificationConfiguration.resolve()
            } catch (error: RuntimeException) {
                throw GradleException("failed to verify IDE source artifact checksums", error)
            }
        }

        val resolvedSourceCount =
            artifactResults
                .resolvedComponents
                .sumOf { component -> component.getArtifacts(SourcesArtifact::class.java).size }
        logger.lifecycle("Resolved $resolvedSourceCount IDE source artifacts for dependency verification.")
    }
}

fun ideArtifactDependencyNotations(
    module: ModuleComponentIdentifier,
    artifactName: String,
): List<String> {
    val prefix = "${module.module}-${module.version}-"
    val suffix = ".jar"
    if (!artifactName.startsWith(prefix) || !artifactName.endsWith(suffix)) {
        return emptyList()
    }
    val classifier = artifactName.removePrefix(prefix).removeSuffix(suffix)
    if (classifier.isBlank()) {
        return emptyList()
    }
    val resolvedSourceNotation = "${module.group}:${module.module}:${module.version}:$classifier@jar"
    val plainSourceNotation = "${module.group}:${module.module}:${module.version}:sources@jar"
    val javadocNotation =
        if (
            module.group == "com.google.protobuf" &&
            (module.module == "protobuf-javalite" || module.module == "protobuf-kotlin-lite")
        ) {
            "${module.group}:${module.module}:${module.version}:javadoc@jar"
        } else {
            null
        }
    return listOfNotNull(resolvedSourceNotation, plainSourceNotation, javadocNotation)
}

tasks.named("check") {
    dependsOn("ktlintCheck", "detekt", "resolveIdeDependencySources", "test")
}
