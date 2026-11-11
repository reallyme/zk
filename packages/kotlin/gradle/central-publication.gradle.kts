// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import org.gradle.api.artifacts.repositories.MavenArtifactRepository
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.jvm.tasks.Jar

val centralArtifactIds =
    mapOf(
        ":" to "zk",
        ":android-native" to "zk-android",
        ":proto-codec" to "zk-proto-codec",
        ":proto-generated" to "zk-proto-generated",
    )
val centralRepository = file(providers.gradleProperty("reallymeZkCentralStaging").get())
val repositoryRoot = rootProject.layout.projectDirectory.dir("../..")
val projectUrl = "https://github.com/reallyme/zk"

allprojects {
    val centralArtifactId = centralArtifactIds[path]
    if (centralArtifactId != null) {
        afterEvaluate {
            val javaSources =
                if (centralArtifactId == "zk-android") {
                    null
                } else {
                    extensions.getByType<SourceSetContainer>().named("main").map { it.allSource }
                }
            val sourcesJar =
                tasks.register<Jar>("centralSourcesJar") {
                    archiveClassifier.set("sources")
                    isPreserveFileTimestamps = false
                    isReproducibleFileOrder = true
                    if (javaSources == null) {
                        from(layout.projectDirectory.dir("src/main"))
                        from(rootProject.layout.projectDirectory.dir("native/jni")) {
                            into("jni")
                        }
                    } else {
                        from(javaSources)
                    }
                    from(repositoryRoot.file("LICENSE-MIT"), repositoryRoot.file("LICENSE-APACHE"))
                }
            val documentationJar =
                tasks.register<Jar>("centralDocumentationJar") {
                    archiveClassifier.set("javadoc")
                    isPreserveFileTimestamps = false
                    isReproducibleFileOrder = true
                    from(repositoryRoot.file("README.md"), repositoryRoot.file("docs/platform-builds.md"))
                }
            extensions.configure<PublishingExtension> {
                repositories.named<MavenArtifactRepository>("localReleaseArtifacts") {
                    url = centralRepository.toURI()
                }
                publications.named<MavenPublication>("release") {
                    check(artifactId == centralArtifactId) { "Unexpected publication artifact ID for ${project.path}" }
                    artifact(sourcesJar)
                    artifact(documentationJar)
                    pom {
                        url.set(projectUrl)
                        licenses {
                            license {
                                name.set("MIT License")
                                url.set("https://opensource.org/license/mit")
                                distribution.set("repo")
                            }
                            license {
                                name.set("Apache License, Version 2.0")
                                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                                distribution.set("repo")
                            }
                        }
                        developers {
                            developer {
                                id.set("reallyme")
                                name.set("ReallyMe Technologies Limited")
                                organization.set("ReallyMe Technologies Limited")
                                organizationUrl.set("https://github.com/reallyme")
                            }
                        }
                        scm {
                            connection.set("scm:git:$projectUrl.git")
                            developerConnection.set("scm:git:ssh://git@github.com/reallyme/zk.git")
                            url.set(projectUrl)
                        }
                    }
                }
            }
        }
    }
}
