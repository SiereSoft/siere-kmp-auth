package dev.siere.auth.sample

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DesktopMainTest {
    @Test
    fun desktopConfigurationRequiresEveryPublicValue() {
        assertNull(DesktopFirebaseConfig.from(emptyMap()))
        assertNull(
            DesktopFirebaseConfig.from(
                mapOf(
                    "SIERE_SAMPLE_FIREBASE_API_KEY" to "api-key",
                    "SIERE_SAMPLE_FIREBASE_APP_ID" to "app-id",
                    "SIERE_SAMPLE_FIREBASE_PROJECT_ID" to "project-id",
                ),
            ),
        )
    }

    @Test
    fun fileStorageRestoresValuesAcrossPlatformInstances() {
        val directory = Files.createTempDirectory("siere-auth-desktop-test").toFile()
        try {
            FileBackedFirebasePlatform(directory).store("session-key", "session-value")

            val recreated = FileBackedFirebasePlatform(directory)
            assertEquals("session-value", recreated.retrieve("session-key"))
            recreated.clear("session-key")
            assertNull(recreated.retrieve("session-key"))
        } finally {
            directory.deleteRecursively()
        }
    }
}
