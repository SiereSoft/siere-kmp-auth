plugins {
    alias(libs.plugins.multiplatform)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose)
}

kotlin {
    jvm()

    sourceSets {
        jvmMain.dependencies {
            implementation(project(":auth-core"))
            implementation(project(":auth-oidc"))
            implementation(compose.desktop.currentOs)
            implementation(compose.material3)
            implementation(libs.kotlinx.coroutines.core)
        }

        jvmTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.serialization.json)
        }
    }
}

compose.desktop {
    application {
        mainClass = "dev.siere.auth.sample.oidc.MainKt"
        nativeDistributions {
            packageName = "Siere OIDC Sample"
            packageVersion = "1.0.0"
        }
    }
}

tasks.withType<Test>().configureEach {
    workingDir(projectDir)
}

tasks.register<Exec>("keycloakUp") {
    group = "application"
    description = "Starts the local Keycloak server and imports the sample realm."
    workingDir(projectDir)
    commandLine("docker", "compose", "up", "--detach", "--wait")
}

tasks.register<Exec>("keycloakDown") {
    group = "application"
    description = "Stops and removes the local Keycloak container."
    workingDir(projectDir)
    commandLine("docker", "compose", "down")
}
