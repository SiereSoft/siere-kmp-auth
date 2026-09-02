import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.multiplatform)
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose)
}

kotlin {
    androidTarget()

    jvm()

    js {
        browser()
        binaries.executable()
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
        binaries.executable()
    }

    listOf(
        iosArm64(),
        iosSimulatorArm64(),
    ).forEach { target ->
        target.binaries.framework {
            baseName = "SampleApp"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(libs.kotlinx.coroutines.core)
            implementation(project(":auth-core"))
            implementation(project(":auth-firebase"))
            implementation(project(":auth-supabase"))
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }

        androidMain.dependencies {
            implementation(libs.androidx.activity.compose)
        }

        jvmMain.dependencies {
            implementation(compose.desktop.currentOs)
        }

        wasmJsMain.dependencies {
            implementation(libs.kotlinx.browser)
        }
    }
}

compose.desktop {
    application {
        mainClass = "dev.siere.auth.sample.DesktopMainKt"
        nativeDistributions {
            packageVersion = "1.0.0"
        }
    }
}

android {
    namespace = "dev.siere.auth.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.siere.auth.sample"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "0.0.1"
    }
}
