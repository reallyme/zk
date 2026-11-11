// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

plugins {
    kotlin("jvm")
    application
}

kotlin {
    explicitApi()
    jvmToolchain(17)
    compilerOptions {
        allWarningsAsErrors = true
    }
}

application {
    mainClass.set("me.really.zk.demo.ReallyMeZkDemoKt")
}

dependencies {
    implementation(project(":"))
    implementation(project(":demo-shared"))
    testImplementation(kotlin("test"))
}
