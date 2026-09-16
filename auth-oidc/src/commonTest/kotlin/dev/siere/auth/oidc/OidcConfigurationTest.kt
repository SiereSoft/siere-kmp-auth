package dev.siere.auth.oidc

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class OidcConfigurationTest {
    @Test
    fun openIdScopeIsAddedByTheFlowAndNeedNotBeConfigured() {
        val configuration = OidcConfiguration("client", "https://issuer.example/.well-known/openid-configuration")

        assertEquals(setOf("profile", "email"), configuration.scopes)
    }

    @Test
    fun reservedAuthorizationParametersCannotBeOverridden() {
        assertFailsWith<IllegalArgumentException> {
            OidcConfiguration(
                clientId = "client",
                discoveryUrl = "https://issuer.example/.well-known/openid-configuration",
                additionalAuthorizationParameters = mapOf("NoNcE" to "attacker-controlled"),
            )
        }
    }

    @Test
    fun defaultStorageNameSeparatesClients() {
        val first = OidcConfiguration("first", "https://issuer.example/.well-known/openid-configuration")
        val second = OidcConfiguration("second", "https://issuer.example/.well-known/openid-configuration")

        assertNotEquals(first.storageName, second.storageName)
    }

    @Test
    fun boundsCallbackLifetimeAndClockSkew() {
        assertFailsWith<IllegalArgumentException> {
            OidcConfiguration(
                "client",
                "https://issuer.example/.well-known/openid-configuration",
                callbackTimeoutMillis = 600_001,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            OidcConfiguration(
                "client",
                "https://issuer.example/.well-known/openid-configuration",
                clockSkewSeconds = 301,
            )
        }
    }
}
