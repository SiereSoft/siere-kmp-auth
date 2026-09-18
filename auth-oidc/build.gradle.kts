import org.gradle.api.publish.maven.MavenPublication

plugins {
    alias(libs.plugins.multiplatform)
    `maven-publish`
}

kotlin {
    explicitApi()

    jvm()

    sourceSets {
        commonMain.dependencies {
            api(project(":auth-core"))
            implementation(libs.kotlinx.coroutines.core)
        }

        jvmMain.dependencies {
            implementation(libs.kotlinx.serialization.json)
        }
        jvmMain.get().kotlin.srcDir(rootProject.file("auth-jvm-shared/src/main/kotlin"))

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        pom {
            name = "Siere KMP Auth OpenID Connect"
            description = "OpenID Connect authentication adapter for Siere KMP Auth."
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
