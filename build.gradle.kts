import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.DetektCreateBaselineTask
import io.gitlab.arturbosch.detekt.extensions.DetektExtension

plugins {
    alias(libs.plugins.multiplatform) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.binaryCompatibility)
    alias(libs.plugins.detekt)
    alias(libs.plugins.ktlint)
}

group = providers.gradleProperty("GROUP").get()
version = providers.gradleProperty("VERSION_NAME").get()

subprojects {
    group = rootProject.group
    version = rootProject.version

    apply(plugin = "io.gitlab.arturbosch.detekt")
    apply(plugin = "org.jlleitschuh.gradle.ktlint")

    configure<DetektExtension> {
        buildUponDefaultConfig = true
        baseline = file("detekt-baseline.xml")
    }

    tasks.withType<Detekt>().configureEach {
        setSource(fileTree("src") { include("**/*.kt") })
    }
    tasks.withType<DetektCreateBaselineTask>().configureEach {
        setSource(fileTree("src") { include("**/*.kt") })
    }
}

apiValidation {
    ignoredProjects.add("sample")

    @OptIn(kotlinx.validation.ExperimentalBCVApi::class)
    klib {
        enabled = true
    }
}

val staticAnalysis =
    tasks.register("staticAnalysis") {
        group = "verification"
        description = "Runs detekt and ktlint checks for every project."
        dependsOn(tasks.named("detekt"), tasks.named("ktlintCheck"))
        dependsOn(
            subprojects.flatMap { project ->
                listOf("${project.path}:detekt", "${project.path}:ktlintCheck")
            },
        )
    }
