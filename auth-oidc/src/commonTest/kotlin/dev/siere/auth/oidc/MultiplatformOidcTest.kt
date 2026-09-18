@file:Suppress("MaxLineLength")

package dev.siere.auth.oidc

import dev.siere.auth.AuthResult
import dev.siere.auth.AuthState
import dev.siere.auth.DispatcherProvider
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.headersOf
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class MultiplatformOidcTest {
    @Test
    fun commonProviderCompletesSignInSessionAndSignOut() =
        runTest {
            val algorithm = CryptographyProvider.Default.get(RSA.PKCS1)
            val keyPair = algorithm.keyPairGenerator(2048.bits, SHA256).generateKey()
            val publicJwk = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.JWK).decodeToString()
            var nonce: String? = null
            val engine =
                MockEngine { request ->
                    val content =
                        when (request.url.encodedPath) {
                            "/.well-known/openid-configuration" ->
                                """{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","id_token_signing_alg_values_supported":["RS256"]}"""
                            "/jwks" -> "{\"keys\":[$publicJwk]}"
                            "/token" -> {
                                val idToken = signedToken(keyPair, checkNotNull(nonce))
                                """{"token_type":"Bearer","access_token":"access","refresh_token":"refresh","expires_in":3600,"id_token":"$idToken"}"""
                            }
                            else -> error("Unexpected request ${request.url}")
                        }
                    respond(
                        content = content,
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
            val http = MultiplatformOidcHttpClient(HttpClient(engine))
            val dispatcher = UnconfinedTestDispatcher(testScheduler)
            val provider =
                MultiplatformOidcAuthProvider(
                    configuration =
                        OidcConfiguration(
                            clientId = "client",
                            discoveryUrl = "https://issuer.example/.well-known/openid-configuration",
                        ),
                    redirectUri = "app://auth/callback",
                    authorizationHandler =
                        OidcAuthorizationHandler { request ->
                            val parameters = Url(request.authorizationUrl).parameters
                            nonce = checkNotNull(parameters["nonce"])
                            "${request.redirectUri}?code=code&state=${parameters["state"]}"
                        },
                    sessionStore = InMemoryOidcSessionStore(),
                    dispatcherProvider = TestDispatchers(dispatcher),
                    nowEpochMillis = { 1_000_000 },
                    http = http,
                )

            val signedIn = provider.signInWithOpenId()

            assertTrue(signedIn is AuthResult.Success)
            assertEquals("https://issuer.example|user-1", signedIn.value.uid)
            assertTrue(provider.authState.value is AuthState.SignedIn)
            val session = provider.currentSession()
            assertTrue(session is AuthResult.Success)
            assertEquals("access", session.value.accessToken)
            assertTrue(provider.signOut().isSuccess)
            assertEquals(AuthState.SignedOut, provider.authState.value)
            provider.close()
        }

    @Test
    fun authorizationFlowUsesPkceAndValidatesTheCallback() =
        runTest {
            val configuration =
                OidcConfiguration(
                    clientId = "client",
                    discoveryUrl = "https://issuer.example/.well-known/openid-configuration",
                )
            var request: OidcAuthorizationRequest? = null
            val flow =
                MultiplatformOidcAuthorizationFlow(
                    configuration = configuration,
                    redirectUri = "app://auth/callback",
                    authorizationHandler =
                        OidcAuthorizationHandler { received ->
                            request = received
                            val state = checkNotNull(Url(received.authorizationUrl).parameters["state"])
                            "${received.redirectUri}?code=authorization-code&state=$state&iss=https%3A%2F%2Fissuer.example"
                        },
                )

            val grant = flow.authorize(metadata())
            val query = Url(checkNotNull(request).authorizationUrl).parameters

            assertEquals("authorization-code", grant.code)
            assertEquals("app://auth/callback", grant.redirectUri)
            assertEquals("S256", query["code_challenge_method"])
            assertTrue(checkNotNull(query["code_challenge"]).isNotBlank())
            assertTrue(checkNotNull(query["scope"]).split(' ').containsAll(listOf("openid", "profile", "email")))
            assertEquals(configuration.clientId, query["client_id"])
        }

    @Test
    fun authorizationFlowRejectsWrongState() =
        runTest {
            val flow =
                MultiplatformOidcAuthorizationFlow(
                    configuration =
                        OidcConfiguration(
                            clientId = "client",
                            discoveryUrl = "https://issuer.example/.well-known/openid-configuration",
                        ),
                    redirectUri = "app://auth/callback",
                    authorizationHandler =
                        OidcAuthorizationHandler { "app://auth/callback?code=attacker&state=wrong" },
                )

            val failure = assertFailsWith<MultiplatformOidcFailure> { flow.authorize(metadata()) }
            assertTrue(failure.error.message.contains("state"))
        }

    @Test
    fun authorizationFlowRejectsARelativeRedirectUri() {
        assertFailsWith<IllegalArgumentException> {
            MultiplatformOidcAuthorizationFlow(
                configuration =
                    OidcConfiguration(
                        clientId = "client",
                        discoveryUrl = "https://issuer.example/.well-known/openid-configuration",
                    ),
                redirectUri = "callback",
                authorizationHandler = OidcAuthorizationHandler { error("Not used") },
            )
        }
    }

    @Test
    fun httpClientRejectsAnOversizedResponse() =
        runTest {
            val engine =
                MockEngine {
                    respond(
                        content = "x".repeat(1024 * 1024 + 1),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
            val http = MultiplatformOidcHttpClient(HttpClient(engine))

            val failure =
                assertFailsWith<MultiplatformOidcFailure> {
                    http.getJson("https://issuer.example/oversized")
                }

            assertTrue(failure.error.message.contains("size limit"))
            http.close()
        }

    @Test
    fun restoreRejectsAStoredIdTokenThatWasNotCryptographicallyVerified() =
        runTest {
            val algorithm = CryptographyProvider.Default.get(RSA.PKCS1)
            val keyPair = algorithm.keyPairGenerator(2048.bits, SHA256).generateKey()
            val publicJwk = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.JWK).decodeToString()
            val header = buildJsonObject { put("alg", JsonPrimitive("RS256")) }.toString().encodeToByteArray()
            val claims =
                buildJsonObject {
                    put("iss", JsonPrimitive("https://attacker.example"))
                    put("sub", JsonPrimitive("admin"))
                    put("aud", JsonPrimitive("client"))
                    put("iat", JsonPrimitive(1))
                    put("exp", JsonPrimitive(2))
                }.toString().encodeToByteArray()
            val forgedToken =
                "${header.encodeMultiplatformBase64Url()}.${claims.encodeMultiplatformBase64Url()}.AA"
            var cleared = false
            val store =
                object : OidcSessionStore {
                    override suspend fun read(): ByteArray =
                        buildJsonObject {
                            put("client_id", JsonPrimitive("client"))
                            put(
                                "discovery_url",
                                JsonPrimitive("https://issuer.example/.well-known/openid-configuration"),
                            )
                            put("access_token", JsonPrimitive("forged-access-token"))
                            put("id_token", JsonPrimitive(forgedToken))
                        }.toString().encodeToByteArray()

                    override suspend fun write(value: ByteArray) = Unit

                    override suspend fun clear() {
                        cleared = true
                    }
                }
            val engine =
                MockEngine { request ->
                    respond(
                        content =
                            when (request.url.encodedPath) {
                                "/.well-known/openid-configuration" ->
                                    """{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","id_token_signing_alg_values_supported":["RS256"]}"""
                                "/jwks" -> "{\"keys\":[$publicJwk]}"
                                else -> error("Unexpected request ${request.url}")
                            },
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
            val dispatcher = UnconfinedTestDispatcher(testScheduler)
            val provider =
                MultiplatformOidcAuthProvider(
                    configuration =
                        OidcConfiguration(
                            clientId = "client",
                            discoveryUrl = "https://issuer.example/.well-known/openid-configuration",
                        ),
                    redirectUri = "app://auth/callback",
                    authorizationHandler = OidcAuthorizationHandler { error("Not used") },
                    sessionStore = store,
                    dispatcherProvider = TestDispatchers(dispatcher),
                    nowEpochMillis = { 1_000_000 },
                    http = MultiplatformOidcHttpClient(HttpClient(engine)),
                )

            assertEquals(AuthState.SignedOut, provider.authState.first { it !is AuthState.Loading })
            assertTrue(cleared)
            provider.close()
        }

    @Test
    fun restoreDoesNotDeleteTheSessionWhenTheStoreCannotBeRead() =
        runTest {
            var cleared = false
            val store =
                object : OidcSessionStore {
                    override suspend fun read(): ByteArray = error("Credential store is temporarily unavailable")

                    override suspend fun write(value: ByteArray) = Unit

                    override suspend fun clear() {
                        cleared = true
                    }
                }
            val dispatcher = UnconfinedTestDispatcher(testScheduler)
            val provider =
                MultiplatformOidcAuthProvider(
                    configuration =
                        OidcConfiguration(
                            clientId = "client",
                            discoveryUrl = "https://issuer.example/.well-known/openid-configuration",
                        ),
                    redirectUri = "app://auth/callback",
                    authorizationHandler = OidcAuthorizationHandler { error("Not used") },
                    sessionStore = store,
                    dispatcherProvider = TestDispatchers(dispatcher),
                    nowEpochMillis = { 1_000_000 },
                    http = MultiplatformOidcHttpClient(HttpClient(MockEngine { error("Not used") })),
                )

            assertEquals(AuthState.SignedOut, provider.authState.first { it !is AuthState.Loading })
            assertTrue(!cleared)
            provider.close()
        }

    @Test
    fun verifiesRs256IdTokensOnTheCommonImplementation() =
        runTest {
            val algorithm = CryptographyProvider.Default.get(RSA.PKCS1)
            val keyPair = algorithm.keyPairGenerator(2048.bits, SHA256).generateKey()
            val publicJwk = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.JWK).decodeToString()
            val header = buildJsonObject { put("alg", JsonPrimitive("RS256")) }.toString().encodeToByteArray()
            val claims =
                buildJsonObject {
                    put("iss", JsonPrimitive("https://issuer.example"))
                    put("sub", JsonPrimitive("user-1"))
                    put("aud", JsonPrimitive("client"))
                    put("iat", JsonPrimitive(900))
                    put("exp", JsonPrimitive(1_100))
                    put("nonce", JsonPrimitive("expected-nonce"))
                }.toString().encodeToByteArray()
            val signingInput =
                "${header.encodeMultiplatformBase64Url()}.${claims.encodeMultiplatformBase64Url()}"
            val signature =
                keyPair.privateKey
                    .signatureGenerator()
                    .generateSignature(signingInput.encodeToByteArray())
                    .encodeMultiplatformBase64Url()
            val token = "$signingInput.$signature"
            val engine =
                MockEngine {
                    respond(
                        content = "{\"keys\":[$publicJwk]}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
            val http = MultiplatformOidcHttpClient(HttpClient(engine))
            val verifier =
                MultiplatformOidcIdTokenVerifier(
                    metadata = metadata(),
                    clientId = "client",
                    clockSkewSeconds = 0,
                    allowInsecureHttpForTesting = false,
                    http = http,
                    nowEpochSeconds = { 1_000 },
                )

            val verified = verifier.verify(token, "expected-nonce")

            assertEquals("user-1", verified.subject)
            assertFailsWith<MultiplatformOidcFailure> {
                verifier.verify(token.dropLast(1) + if (token.last() == 'A') "B" else "A", "expected-nonce")
            }
            http.close()
        }

    @Test
    fun verifiesEs256IdTokensOnTheCommonImplementation() =
        runTest {
            val algorithm = CryptographyProvider.Default.get(ECDSA)
            val keyPair = algorithm.keyPairGenerator(EC.Curve.P256).generateKey()
            val publicJwk = keyPair.publicKey.encodeToByteArray(EC.PublicKey.Format.JWK).decodeToString()
            val header = buildJsonObject { put("alg", JsonPrimitive("ES256")) }.toString().encodeToByteArray()
            val claims =
                buildJsonObject {
                    put("iss", JsonPrimitive("https://issuer.example"))
                    put("sub", JsonPrimitive("user-1"))
                    put("aud", JsonPrimitive("client"))
                    put("iat", JsonPrimitive(900))
                    put("exp", JsonPrimitive(1_100))
                    put("nonce", JsonPrimitive("expected-nonce"))
                }.toString().encodeToByteArray()
            val signingInput =
                "${header.encodeMultiplatformBase64Url()}.${claims.encodeMultiplatformBase64Url()}"
            val signature =
                keyPair.privateKey
                    .signatureGenerator(SHA256, ECDSA.SignatureFormat.RAW)
                    .generateSignature(signingInput.encodeToByteArray())
                    .encodeMultiplatformBase64Url()
            val token = "$signingInput.$signature"
            val engine =
                MockEngine {
                    respond(
                        content = "{\"keys\":[$publicJwk]}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json"),
                    )
                }
            val http = MultiplatformOidcHttpClient(HttpClient(engine))
            val verifier =
                MultiplatformOidcIdTokenVerifier(
                    metadata = metadata().copy(supportedAlgorithms = setOf("ES256")),
                    clientId = "client",
                    clockSkewSeconds = 0,
                    allowInsecureHttpForTesting = false,
                    http = http,
                    nowEpochSeconds = { 1_000 },
                )

            assertEquals("user-1", verifier.verify(token, "expected-nonce").subject)
            http.close()
        }

    @Test
    fun base64UrlCodecRoundTripsWithoutPadding() {
        val values = listOf(byteArrayOf(), byteArrayOf(0), byteArrayOf(1, 2), byteArrayOf(1, 2, 3), ByteArray(32) { it.toByte() })
        values.forEach { value ->
            val encoded = value.encodeMultiplatformBase64Url()
            assertTrue('=' !in encoded)
            assertTrue(value.contentEquals(encoded.decodeMultiplatformBase64Url()))
        }
    }

    private fun metadata(): MultiplatformOidcMetadata =
        MultiplatformOidcMetadata(
            issuer = "https://issuer.example",
            authorizationEndpoint = "https://issuer.example/authorize",
            tokenEndpoint = "https://issuer.example/token",
            jwksUri = "https://issuer.example/jwks",
            supportedAlgorithms = setOf("RS256"),
        )

    private suspend fun signedToken(
        keyPair: RSA.PKCS1.KeyPair,
        nonce: String,
    ): String {
        val header = buildJsonObject { put("alg", JsonPrimitive("RS256")) }.toString().encodeToByteArray()
        val claims =
            buildJsonObject {
                put("iss", JsonPrimitive("https://issuer.example"))
                put("sub", JsonPrimitive("user-1"))
                put("aud", JsonPrimitive("client"))
                put("iat", JsonPrimitive(900))
                put("exp", JsonPrimitive(1_100))
                put("nonce", JsonPrimitive(nonce))
                put("email", JsonPrimitive("person@example.com"))
                put("email_verified", JsonPrimitive(true))
            }.toString().encodeToByteArray()
        val signingInput = "${header.encodeMultiplatformBase64Url()}.${claims.encodeMultiplatformBase64Url()}"
        val signature =
            keyPair.privateKey
                .signatureGenerator()
                .generateSignature(signingInput.encodeToByteArray())
                .encodeMultiplatformBase64Url()
        return "$signingInput.$signature"
    }

    private class TestDispatchers(
        dispatcher: kotlinx.coroutines.CoroutineDispatcher,
    ) : DispatcherProvider {
        override val main = dispatcher
        override val default = dispatcher
        override val io = dispatcher
        override val unconfined = dispatcher
    }
}
