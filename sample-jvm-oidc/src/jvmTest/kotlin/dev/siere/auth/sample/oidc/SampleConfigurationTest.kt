package dev.siere.auth.sample.oidc

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SampleConfigurationTest {
    @Test
    fun defaultsTargetTheImportedLocalRealm() {
        val configuration = SampleConfiguration.fromEnvironment(emptyMap())
        val oidc = configuration.toOidcConfiguration()

        assertEquals("siere-jvm-oidc", oidc.clientId)
        assertEquals(
            "http://127.0.0.1:8080/realms/siere/.well-known/openid-configuration",
            oidc.discoveryUrl,
        )
        assertEquals(setOf("profile", "email"), oidc.scopes)
        assertTrue(oidc.allowInsecureHttpForTesting)
    }

    @Test
    fun environmentOverridesSupportAHostedProviderWithoutWeakeningHttps() {
        val configuration =
            SampleConfiguration
                .fromEnvironment(
                    mapOf(
                        "SIERE_OIDC_CLIENT_ID" to "hosted-client",
                        "SIERE_OIDC_DISCOVERY_URL" to "https://login.example/.well-known/openid-configuration",
                        "SIERE_OIDC_PROVIDER_ID" to "hosted",
                    ),
                ).toOidcConfiguration()

        assertEquals("hosted-client", configuration.clientId)
        assertEquals("hosted", configuration.providerId)
        assertFalse(configuration.allowInsecureHttpForTesting)
    }

    @Test
    fun onlyNumericLoopbackDiscoveryEnablesTestHttp() {
        val localhost =
            SampleConfiguration.fromEnvironment(
                mapOf(
                    "SIERE_OIDC_DISCOVERY_URL" to
                        "http://localhost:8080/realms/siere/.well-known/openid-configuration",
                ),
            )
        val deceptive =
            SampleConfiguration.fromEnvironment(
                mapOf(
                    "SIERE_OIDC_DISCOVERY_URL" to
                        "http://127.0.0.1.example/realms/siere/.well-known/openid-configuration",
                ),
            )

        assertFalse(localhost.allowInsecureLoopback)
        assertFalse(deceptive.allowInsecureLoopback)
    }

    @Test
    fun importedRealmDefinesAPublicPkceClientAndDemoUser() {
        val realmPath = Path.of("keycloak", "siere-realm.json")
        val realm = Json.parseToJsonElement(Files.readString(realmPath)).jsonObject
        val client =
            realm
                .getValue("clients")
                .jsonArray
                .single()
                .jsonObject
        val user =
            realm
                .getValue("users")
                .jsonArray
                .single()
                .jsonObject

        assertEquals("siere-jvm-oidc", client.getValue("clientId").jsonPrimitive.content)
        assertEquals("true", client.getValue("publicClient").jsonPrimitive.content)
        assertEquals(
            "S256",
            client
                .getValue("attributes")
                .jsonObject
                .getValue("pkce.code.challenge.method")
                .jsonPrimitive.content,
        )
        assertEquals(
            "http://127.0.0.1/callback",
            client
                .getValue("redirectUris")
                .jsonArray
                .single()
                .jsonPrimitive.content,
        )
        assertEquals("demo", user.getValue("username").jsonPrimitive.content)
        assertEquals("demo@example.invalid", user.getValue("email").jsonPrimitive.content)
        assertEquals(
            setOf("profile", "email"),
            client
                .getValue("defaultClientScopes")
                .jsonArray
                .map { it.jsonPrimitive.content }
                .toSet(),
        )
        assertTrue(client.getValue("optionalClientScopes").jsonArray.isEmpty())
    }
}
