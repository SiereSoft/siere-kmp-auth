package dev.siere.auth.supabase

import io.github.jan.supabase.auth.user.Identity
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.auth.user.UserSession
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

class SupabaseUserMappingTest {
    @Test
    fun mapsNormalizedIdentityFields() {
        val user =
            UserInfo(
                id = "user-123",
                aud = "authenticated",
                email = "person@example.test",
                emailConfirmedAt = Instant.parse("2026-01-02T03:04:05Z"),
                phone = "+359875555555",
                isAnonymous = false,
                userMetadata =
                    buildJsonObject {
                        put("full_name", "Person Example")
                        put("avatar_url", "https://example.test/avatar.png")
                    },
                identities =
                    listOf(
                        Identity(
                            id = "identity-1",
                            identityData = buildJsonObject {},
                            provider = "google",
                            userId = "user-123",
                        ),
                        Identity(
                            id = "identity-2",
                            identityData = buildJsonObject {},
                            provider = "email",
                            userId = "user-123",
                        ),
                    ),
            )

        val mapped = user.toAuthUser()

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
    fun handlesSparseAnonymousUser() {
        val mapped =
            UserInfo(
                id = "guest-123",
                aud = "authenticated",
                phone = "",
                isAnonymous = true,
            ).toAuthUser()

        assertEquals("guest-123", mapped.uid)
        assertNull(mapped.displayName)
        assertNull(mapped.email)
        assertNull(mapped.photoUrl)
        assertNull(mapped.phoneNumber)
        assertTrue(mapped.isAnonymous)
        assertEquals(listOf("anonymous"), mapped.providerIds)
    }

    @Test
    fun malformedMetadataCannotBreakUserMapping() {
        val mapped =
            UserInfo(
                id = "user-malformed-metadata",
                aud = "authenticated",
                userMetadata =
                    buildJsonObject {
                        put("full_name", buildJsonObject { put("nested", "value") })
                        put("name", buildJsonArray { add(JsonNull) })
                        put("avatar_url", JsonNull)
                    },
            ).toAuthUser()

        assertNull(mapped.displayName)
        assertNull(mapped.photoUrl)
    }

    @Test
    fun mapsSessionCredentialsAndExpiry() {
        val expiry = Instant.parse("2099-12-31T23:59:59Z")
        val session =
            UserSession(
                accessToken = "access-token",
                refreshToken = "refresh-token",
                expiresIn = 3_600,
                tokenType = "bearer",
                user = UserInfo(id = "user-123", aud = "authenticated"),
                expiresAt = expiry,
            ).toAuthSession()!!

        assertEquals("access-token", session.accessToken)
        assertEquals("refresh-token", session.refreshToken)
        assertEquals(expiry.toEpochMilliseconds(), session.expiresAtEpochMillis)
        assertEquals("user-123", session.user.uid)
    }

    @Test
    fun sessionWithoutUserDoesNotProduceAuthSession() {
        val mapped =
            UserSession(
                accessToken = "access-token",
                refreshToken = "refresh-token",
                expiresIn = 3_600,
                tokenType = "bearer",
                user = null,
                expiresAt = Instant.parse("2099-12-31T23:59:59Z"),
            ).toAuthSession()

        assertNull(mapped)
    }

    @Test
    fun providerIdsUseTheProviderNeutralVocabulary() {
        assertEquals("google.com", canonicalProviderId("google"))
        assertEquals("google.com", canonicalProviderId("google.com"))
        assertEquals("apple.com", canonicalProviderId("apple"))
        assertEquals("password", canonicalProviderId("email"))
        assertEquals("phone", canonicalProviderId("phone"))
        assertEquals("anonymous", canonicalProviderId("anonymous"))
        assertEquals("custom", canonicalProviderId("custom"))
    }

    @Test
    fun sessionRefreshDecisionCoversForcedExpiredAndValidSessions() {
        val now = Instant.parse("2026-09-01T08:00:00Z")

        assertTrue(shouldRefreshSession(now, now, forceRefresh = false))
        assertTrue(
            shouldRefreshSession(
                Instant.parse("2026-09-01T07:59:59Z"),
                now,
                forceRefresh = false,
            ),
        )
        assertTrue(
            shouldRefreshSession(
                Instant.parse("2026-09-01T09:00:00Z"),
                now,
                forceRefresh = true,
            ),
        )
        assertFalse(
            shouldRefreshSession(
                Instant.parse("2026-09-01T09:00:00Z"),
                now,
                forceRefresh = false,
            ),
        )
    }
}
