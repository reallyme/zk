// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import org.gradle.api.publish.maven.MavenPublication

plugins {
    id("com.android.library")
    id("maven-publish")
}

val nativePackageMode =
    providers
        .gradleProperty("reallymeZkAndroidNativePackageMode")
        .orElse(
            providers
                .gradleProperty("reallymeZkClaimBundle4Diagnostic")
                .map { enabled ->
                    if (enabled == "true") {
                        "diagnostic-exact-source"
                    } else {
                        "production"
                    }
                },
        )
        .orElse("production")
val diagnosticExactSourceMode = nativePackageMode.map { it == "diagnostic-exact-source" }
check(nativePackageMode.get() == "production" || diagnosticExactSourceMode.get()) {
    "unsupported Android native package mode"
}
val localArtifactRoot = rootProject.layout.projectDirectory.dir("../../release-artifacts/modern-v1-bb-6.0.0")
val androidJniDirectory =
    localArtifactRoot.dir(
        if (diagnosticExactSourceMode.get()) {
            "android-platform-jni-diagnostic"
        } else {
            "android-platform-jni"
        },
    )
val androidJniLibrary = androidJniDirectory.file("arm64-v8a/libreallyme_zk_platform_jni.so")
val androidCppSharedLibrary = androidJniDirectory.file("arm64-v8a/libc++_shared.so")
val androidJniMetadata = androidJniDirectory.file("ReallyMeZKPlatformJNI.build.tsv")
val androidPlatformFfiMetadata =
    localArtifactRoot.file(
        if (diagnosticExactSourceMode.get()) {
            "android-platform-ffi-diagnostic/arm64-v8a/ReallyMeZKPlatformFFI.build.tsv"
        } else {
            "android-platform-ffi/arm64-v8a/ReallyMeZKPlatformFFI.build.tsv"
        },
    )
val androidReleaseAar = layout.buildDirectory.file("outputs/aar/android-native-release.aar")
val centralStaging = providers.gradleProperty("reallymeZkCentralStaging")
val publishedAndroidAarPath = "me/really/zk-android/${rootProject.version}/zk-android-${rootProject.version}.aar"
val publishedAndroidReleaseAar =
    if (centralStaging.isPresent) {
        layout.projectDirectory.file("${centralStaging.get()}/$publishedAndroidAarPath")
    } else {
        localArtifactRoot.file("android-maven/$publishedAndroidAarPath")
    }
val symbolCheckScript = rootProject.layout.projectDirectory.file("../../scripts/check-platform-ffi-symbols.sh")
val freshnessCheckScript = rootProject.layout.projectDirectory.file("../../scripts/check-android-platform-jni-freshness.sh")
val expectedAndroidJniSha256 = "b7f7069cf1a859c5cb9ff27b29bb5dc5b5d04164fc00e8dcbf9dbf255f1c716b"
val expectedAndroidCppSha256 = "7466ed097631a564ed6bff0b47768caa76bf03270d2047b5a65c03f497b824df"
val expectedAndroidAarJniSha256 = "b7f7069cf1a859c5cb9ff27b29bb5dc5b5d04164fc00e8dcbf9dbf255f1c716b"
val expectedAndroidAarCppSha256 = "b5d97c38a728afe28d341cda3369f512d35eaf9c680c1b0563cd6a63e395230f"
val androidJniAarEntryPath = "jni/arm64-v8a/libreallyme_zk_platform_jni.so"
val androidCppAarEntryPath = "jni/arm64-v8a/libc++_shared.so"
val androidAarNegativeMarker =
    layout.buildDirectory.file("tmp/android-native-aar-negative/negative-fixtures-passed.txt")
val verifyAndroidNativeLibrary =
    tasks.register("verifyAndroidNativeLibrary") {
        inputs.property("androidJniLibraryPath", androidJniLibrary.asFile.absolutePath)
        inputs.property("androidCppSharedLibraryPath", androidCppSharedLibrary.asFile.absolutePath)
        inputs.property("androidJniMetadataPath", androidJniMetadata.asFile.absolutePath)
        inputs.property("androidPlatformFfiMetadataPath", androidPlatformFfiMetadata.asFile.absolutePath)
        inputs.property("nativePackageMode", nativePackageMode)
        inputs.property("expectedAndroidJniSha256", expectedAndroidJniSha256)
        inputs.property("expectedAndroidCppSha256", expectedAndroidCppSha256)
        doLast {
            if (diagnosticExactSourceMode.get()) {
                requireDiagnosticExactSourceNative(
                    androidJniLibrary.asFile,
                    androidCppSharedLibrary.asFile,
                    androidJniMetadata.asFile,
                    androidPlatformFfiMetadata.asFile,
                )
            } else {
                requirePinnedFile(androidJniLibrary.asFile, expectedAndroidJniSha256)
                requirePinnedFile(androidCppSharedLibrary.asFile, expectedAndroidCppSha256)
            }
        }
    }

val checkAndroidJniFreshness =
    tasks.register<Exec>("checkAndroidJniFreshness") {
        inputs.file(freshnessCheckScript)
        inputs.property("androidJniLibraryPath", androidJniLibrary.asFile.absolutePath)
        inputs.property("androidCppSharedLibraryPath", androidCppSharedLibrary.asFile.absolutePath)
        inputs.property("androidJniMetadataPath", androidJniMetadata.asFile.absolutePath)
        dependsOn(verifyAndroidNativeLibrary)
        if (diagnosticExactSourceMode.get()) {
            environment("PLATFORM_FFI_DIR", androidPlatformFfiMetadata.asFile.parentFile.absolutePath)
            environment("OUTPUT_ROOT", androidJniDirectory.asFile.absolutePath)
            environment("EXPECTED_CARGO_FEATURES", "native,diagnostic-exact-source")
        }
        commandLine(freshnessCheckScript.asFile.absolutePath)
    }

val checkAndroidJniSymbols =
    tasks.register<Exec>("checkAndroidJniSymbols") {
        inputs.file(symbolCheckScript)
        inputs.property("androidJniLibraryPath", androidJniLibrary.asFile.absolutePath)
        dependsOn(checkAndroidJniFreshness)
        commandLine(
            symbolCheckScript.asFile.absolutePath,
            "android-jni",
            androidJniLibrary.asFile.absolutePath,
        )
    }

val verifyAndroidAarNativeLibraries =
    tasks.register("verifyAndroidAarNativeLibraries") {
        inputs.file(androidReleaseAar)
        inputs.property("expectedAndroidAarJniSha256", expectedAndroidAarJniSha256)
        inputs.property("expectedAndroidAarCppSha256", expectedAndroidAarCppSha256)
        inputs.file(androidJniLibrary)
        inputs.property("nativePackageMode", nativePackageMode)
        dependsOn("bundleReleaseAar")
        doLast {
            requirePinnedAarEntry(
                androidReleaseAar.get().asFile,
                androidJniAarEntryPath,
                if (diagnosticExactSourceMode.get()) {
                    sha256(androidJniLibrary.asFile)
                } else {
                    expectedAndroidAarJniSha256
                },
            )
            requirePinnedAarEntry(
                androidReleaseAar.get().asFile,
                androidCppAarEntryPath,
                expectedAndroidAarCppSha256,
            )
        }
    }

val verifyAndroidAarNativeLibraryNegativeFixtures =
    tasks.register("verifyAndroidAarNativeLibraryNegativeFixtures") {
        outputs.file(androidAarNegativeMarker)
        doLast {
            val root = androidAarNegativeMarker.get().asFile.parentFile
            root.mkdirs()
            val missingAar = File(root, "missing-jni.aar")
            writeAarFixture(
                missingAar,
                mapOf(androidCppAarEntryPath to byteArrayOf(0x01)),
            )
            checkFails { requirePinnedAarEntry(missingAar, androidJniAarEntryPath, expectedAndroidAarJniSha256) }

            val tamperedAar = File(root, "tampered-jni.aar")
            writeAarFixture(
                tamperedAar,
                mapOf(androidJniAarEntryPath to byteArrayOf(0x02)),
            )
            checkFails { requirePinnedAarEntry(tamperedAar, androidJniAarEntryPath, expectedAndroidAarJniSha256) }

            androidAarNegativeMarker.get().asFile.writeText("passed\n")
        }
    }

android {
    namespace = "me.really.zk.platformnative"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        minSdk = 26
    }

    publishing {
        singleVariant("release")
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(androidJniDirectory.asFile.absolutePath)
        }
    }
}

dependencies {
    api(project(":"))
}

publishing {
    repositories {
        maven {
            name = "localReleaseArtifacts"
            url = uri(localArtifactRoot.dir("android-maven").asFile)
        }
    }
    publications {
        create<MavenPublication>("release") {
            groupId = rootProject.group.toString()
            artifactId = "zk-android"
            version = rootProject.version.toString()
            pom {
                name.set("ReallyMe ZK Android Native Provider")
                description.set("Android native provider package for ReallyMe zero-knowledge proof operations.")
                if (!centralStaging.isPresent) {
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

afterEvaluate {
    publishing.publications.named<MavenPublication>("release") {
        from(components["release"])
    }
}

val verifyPublishedAndroidAarNativeLibraries =
    tasks.register("verifyPublishedAndroidAarNativeLibraries") {
        inputs.file(publishedAndroidReleaseAar)
        inputs.property("expectedAndroidAarJniSha256", expectedAndroidAarJniSha256)
        inputs.property("expectedAndroidAarCppSha256", expectedAndroidAarCppSha256)
        dependsOn("publishReleasePublicationToLocalReleaseArtifactsRepository")
        doLast {
            requirePinnedAarEntry(
                publishedAndroidReleaseAar.asFile,
                androidJniAarEntryPath,
                if (diagnosticExactSourceMode.get()) {
                    sha256(androidJniLibrary.asFile)
                } else {
                    expectedAndroidAarJniSha256
                },
            )
            requirePinnedAarEntry(
                publishedAndroidReleaseAar.asFile,
                androidCppAarEntryPath,
                expectedAndroidAarCppSha256,
            )
        }
    }

tasks.named("preBuild") {
    dependsOn(checkAndroidJniSymbols)
}

tasks.named("check") {
    dependsOn(
        "assembleRelease",
        checkAndroidJniSymbols,
        verifyAndroidAarNativeLibraries,
        verifyAndroidAarNativeLibraryNegativeFixtures,
        verifyPublishedAndroidAarNativeLibraries,
    )
}

fun requirePinnedFile(
    file: File,
    expectedSha256: String,
) {
    check(file.isFile) { "missing required Android native library: ${file.absolutePath}" }
    val actualSha256 = sha256(file)
    check(actualSha256 == expectedSha256) {
        "Android native library ${file.absolutePath} has SHA-256 $actualSha256"
    }
}

fun requireDiagnosticExactSourceNative(
    jniLibrary: File,
    cppSharedLibrary: File,
    metadata: File,
    platformMetadata: File,
) {
    check(jniLibrary.isFile) { "missing required Android native library: ${jniLibrary.absolutePath}" }
    check(cppSharedLibrary.isFile) { "missing required Android C++ runtime: ${cppSharedLibrary.absolutePath}" }
    check(metadata.isFile) { "missing Android native metadata: ${metadata.absolutePath}" }
    val metadataFields =
        metadata
            .readLines()
            .map { line -> line.split('\t') }
            .filter { fields -> fields.size == 2 }
            .associate { fields -> fields[0] to fields[1] }
    check(metadataFields["jni_library_sha256"] == sha256(jniLibrary)) {
        "Android diagnostic JNI library does not match build metadata"
    }
    check(metadataFields["libcxx_shared_sha256"] == sha256(cppSharedLibrary)) {
        "Android diagnostic C++ runtime does not match build metadata"
    }
    val platformMetadataSha256 =
        metadataFields["platform_metadata_sha256"]
            ?: error("Android diagnostic native metadata does not name platform metadata")
    check(platformMetadata.isFile) {
        "missing Android platform FFI metadata: ${platformMetadata.absolutePath}"
    }
    check(sha256(platformMetadata) == platformMetadataSha256) {
        "Android diagnostic platform metadata hash does not match JNI metadata"
    }
    val cargoFeatures =
        platformMetadata
            .readLines()
            .map { line -> line.split('\t') }
            .firstOrNull { fields -> fields.size == 2 && fields[0] == "cargo_features" }
            ?.get(1)
            ?: error("Android diagnostic platform metadata does not name Cargo features")
    check(cargoFeatures.split(',', ' ').contains("native")) {
        "Android diagnostic native library was not built with native feature"
    }
    check(cargoFeatures.split(',', ' ').contains("diagnostic-exact-source")) {
        "Android diagnostic native library was not built with diagnostic-exact-source feature"
    }
}

fun sha256(bytes: ByteArray): String =
    MessageDigest
        .getInstance("SHA-256")
        .digest(bytes)
        .joinToString(separator = "") { byte -> "%02x".format(byte) }

fun sha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(1024 * 1024)
    FileInputStream(file).use { input ->
        while (true) {
            val count = input.read(buffer)
            if (count < 0) {
                break
            }
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString(separator = "") { byte -> "%02x".format(byte) }
}

fun requirePinnedAarEntry(
    aar: File,
    entryPath: String,
    expectedSha256: String,
) {
    check(aar.isFile) { "missing Android native AAR: ${aar.absolutePath}" }
    ZipFile(aar).use { zip ->
        val entry = zip.getEntry(entryPath)
            ?: error("missing Android native library in AAR: $entryPath")
        val actualSha256 = sha256(zip.getInputStream(entry))
        check(actualSha256 == expectedSha256) {
            "Android native library $entryPath inside ${aar.absolutePath} has SHA-256 $actualSha256"
        }
    }
}

fun sha256(input: InputStream): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(1024 * 1024)
    input.use { stream ->
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) {
                break
            }
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString(separator = "") { byte -> "%02x".format(byte) }
}

fun writeAarFixture(
    aar: File,
    entries: Map<String, ByteArray>,
) {
    FileOutputStream(aar).use { file ->
        ZipOutputStream(file).use { zip ->
            for ((path, bytes) in entries) {
                zip.putNextEntry(ZipEntry(path))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
    }
}

fun checkFails(block: () -> Unit) {
    val failed =
        try {
            block()
            false
        } catch (_: IllegalStateException) {
            true
        }
    check(failed) { "Android AAR native-library verification accepted an invalid fixture" }
}
