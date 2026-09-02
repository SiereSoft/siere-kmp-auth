package dev.siere.auth.sample

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ClientConfigurationTest {
    @Test
    fun configuredProviderStartsSelected() {
        val options =
            listOf(
                ProviderOption("Demo") { DemoAuthProvider() },
                ProviderOption("Firebase") { DemoAuthProvider() },
            )

        assertEquals(1, initialProviderIndex(options))
        assertEquals(0, initialProviderIndex(options.take(1)))
    }

    @Test
    fun acceptsPublishableAndLegacyAnonKeyShapes() {
        assertEquals("sb_publishable_example", requirePublishableSupabaseKey("sb_publishable_example"))
        assertEquals("legacy-anon-jwt", requirePublishableSupabaseKey(" legacy-anon-jwt "))
    }

    @Test
    fun rejectsRecognizableServerSideSecrets() {
        assertFailsWith<IllegalArgumentException> {
            requirePublishableSupabaseKey("sb_secret_example")
        }
        assertFailsWith<IllegalArgumentException> {
            requirePublishableSupabaseKey("service_role_example")
        }
        val legacyServiceRoleJwt =
            "eyJhbGciOiJIUzI1NiJ9." + "eyJyb2xlIjoic2VydmljZV9yb2xlIn0" + ".signature"
        assertFailsWith<IllegalArgumentException> {
            requirePublishableSupabaseKey(legacyServiceRoleJwt)
        }
    }

    @Test
    fun invalidOptionalKeyIsOmittedWithoutThrowing() {
        assertNull(publishableSupabaseKeyOrNull(""))
        assertNull(publishableSupabaseKeyOrNull("sb_secret_example"))
    }

    @Test
    fun backendDisplayShowsOnlyTheConfiguredOrigin() {
        assertEquals("https://project.supabase.co", displayBackendOrigin("https://project.supabase.co/auth/v1"))
        assertEquals("https://project.firebaseapp.com", displayBackendOrigin("project.firebaseapp.com"))
        assertEquals("http://localhost:54321", displayBackendOrigin("http://localhost:54321/path?ignored=true"))
    }
}
