import org.gradle.api.publish.maven.MavenPublication
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl

plugins {
    alias(libs.plugins.multiplatform)
    alias(libs.plugins.android.library)
    `maven-publish`
}

kotlin {
    explicitApi()

    jvm()

    androidTarget {
        publishLibraryVariants("release")
    }

    js {
        browser()
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
    }

    iosArm64()
    iosSimulatorArm64()

    applyDefaultHierarchyTemplate()

    sourceSets {
        commonMain.dependencies {
            api(project(":auth-core"))
            implementation(libs.kotlinx.coroutines.core)
            api(libs.supabase.auth)
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }

        // Batteries included: each target ships a matching Ktor engine
        jvmMain.dependencies { implementation(libs.ktor.client.cio) }
        androidMain.dependencies { implementation(libs.ktor.client.okhttp) }
        iosMain.dependencies { implementation(libs.ktor.client.darwin) }
        jsMain.dependencies { implementation(libs.ktor.client.js) }
        wasmJsMain.dependencies { implementation(libs.ktor.client.js) }
    }
}

android {
    namespace = "dev.siere.auth.supabase"
    compileSdk = 35
    defaultConfig {
        minSdk = 30
    }
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        pom {
            name = "Siere KMP Auth Supabase"
            description = "Supabase authentication adapter for Siere KMP Auth."
            url = "https://github.com/SiereSoft/siere-kmp-auth"
            licenses {
                license {
                    name = "The Apache License, Version 2.0"
                    url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                }
            }
            scm {
                url = "https://github.com/SiereSoft/siere-kmp-auth"
                connection = "scm:git:https://github.com/SiereSoft/siere-kmp-auth.git"
            }
        }
    }
    repositories.maven {
        name = "GitHubPackages"
        url = uri("https://maven.pkg.github.com/sieresoft/siere-kmp-auth")
        credentials {
            username =
                providers
                    .gradleProperty("gpr.user")
                    .orElse(providers.environmentVariable("GITHUB_ACTOR"))
                    .orNull
            password =
                providers
                    .gradleProperty("gpr.key")
                    .orElse(providers.environmentVariable("GITHUB_TOKEN"))
                    .orNull
        }
    }
}
