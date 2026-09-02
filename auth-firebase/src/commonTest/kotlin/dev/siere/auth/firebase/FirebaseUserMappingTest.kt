package dev.siere.auth.firebase

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FirebaseUserMappingTest {
    @Test
    fun mapsNormalizedIdentityFieldsAndProviderIds() {
        val mapped =
            firebaseAuthUser(
                uid = "user-123",
                displayName = "Person Example",
                email = "person@example.test",
                isEmailVerified = true,
                photoUrl = "https://example.test/avatar.png",
                phoneNumber = "+359875555555",
                isAnonymous = false,
                providerIds = listOf("google", "password", "google.com", ""),
            )

        assertEquals("user-123", mapped.uid)
        assertEquals("Person Example", mapped.displayName)
        assertEquals("person@example.test", mapped.email)
        assertTrue(mapped.isEmailVerified)
        assertEquals("https://example.test/avatar.png", mapped.photoUrl)
        assertEquals("+359875555555", mapped.phoneNumber)
        assertFalse(mapped.isAnonymous)
        assertEquals(listOf("google.com", "password"), mapped.providerIds)
    }

    @Test
    fun marksSparseAnonymousIdentityWithCanonicalProviderId() {
        val mapped =
            firebaseAuthUser(
                uid = "guest-123",
                displayName = null,
                email = null,
                isEmailVerified = false,
                photoUrl = null,
                phoneNumber = null,
                isAnonymous = true,
                providerIds = emptyList(),
            )

        assertNull(mapped.displayName)
        assertNull(mapped.email)
        assertNull(mapped.photoUrl)
        assertNull(mapped.phoneNumber)
        assertFalse(mapped.isEmailVerified)
        assertTrue(mapped.isAnonymous)
        assertEquals(listOf("anonymous"), mapped.providerIds)
    }

    @Test
    fun canonicalizesKnownProviderAliasesAndPreservesCustomProviders() {
        assertEquals("google.com", canonicalFirebaseProviderId("google"))
        assertEquals("apple.com", canonicalFirebaseProviderId("apple"))
        assertEquals("password", canonicalFirebaseProviderId("email"))
        assertEquals("phone", canonicalFirebaseProviderId("phone"))
        assertEquals("anonymous", canonicalFirebaseProviderId("anonymous"))
        assertEquals("custom", canonicalFirebaseProviderId("custom"))
    }
}
