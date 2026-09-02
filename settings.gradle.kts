rootProject.name = "siere-kmp-auth"

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        if (providers.gradleProperty("siereUseMavenLocal").orNull == "true") {
            mavenLocal()
        }
        val githubPackagesUser =
            providers.gradleProperty("gpr.user").orElse(providers.environmentVariable("GITHUB_ACTOR")).orNull
        val githubPackagesToken =
            providers.gradleProperty("gpr.key").orElse(providers.environmentVariable("GITHUB_TOKEN")).orNull
        if (!githubPackagesUser.isNullOrBlank() && !githubPackagesToken.isNullOrBlank()) {
            maven {
                name = "SiereGitHubPackages"
                url = uri("https://maven.pkg.github.com/sieresoft/siere-kmp-auth")
                credentials {
                    username = githubPackagesUser
                    password = githubPackagesToken
                }
                content {
                    includeGroup("dev.gitlive")
                }
            }
        }
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

include(":auth-core")
include(":auth-firebase")
include(":auth-supabase")
include(":sample")
