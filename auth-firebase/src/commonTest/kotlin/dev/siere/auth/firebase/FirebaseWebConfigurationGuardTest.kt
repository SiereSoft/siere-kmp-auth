package dev.siere.auth.firebase

import kotlin.test.Test
import kotlin.test.assertFailsWith

class FirebaseWebConfigurationGuardTest {
    private val first =
        FirebaseWebOptions(
            apiKey = "public-api-key-a",
            authDomain = "project-a.example.test",
            projectId = "project-a",
            applicationId = "app-a",
        )

    @Test
    fun acceptsRepeatedProvidersForTheSameFirebaseApp() {
        requireCompatibleWebConfiguration(
            first,
            first.copy(appVerificationDisabledForTesting = true),
        )
    }

    @Test
    fun rejectsASecondDifferentFirebaseAppInsteadOfSilentlyReusingTheFirst() {
        assertFailsWith<IllegalArgumentException> {
            requireCompatibleWebConfiguration(first, first.copy(projectId = "project-b"))
        }
    }
}
