@file:Suppress("LongMethod", "MagicNumber", "MaxLineLength")

package dev.siere.auth.oidc

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthState
import dev.siere.auth.DefaultDispatcherProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class OidcAuthProviderTest {
    @Test
    fun restoresAProtectedSessionAndClearsMalformedPersistence() =
        runBlocking {
            val issuer = "https://issuer.example"
            val configuration = testConfiguration(issuer)
            val validStore = MemoryStore().apply { value = storedTokenSet(issuer, "desktop-client").serialize(configuration) }
            val restored = OidcAuthProvider(configuration, JvmOidcBrowserLauncher { false }, validStore)
            try {
                val state = restored.authState.first { it !is AuthState.Loading }
                assertEquals("$issuer|restored-subject", (state as AuthState.SignedIn).user.uid)
                assertEquals("restored-access", restored.currentSession().getOrNull()?.accessToken)
            } finally {
                restored.close()
            }

            val malformedStore = MemoryStore().apply { value = "not-json".encodeToByteArray() }
            val malformed = OidcAuthProvider(testConfiguration(issuer), JvmOidcBrowserLauncher { false }, malformedStore)
            try {
                assertIs<AuthState.SignedOut>(malformed.authState.first { it !is AuthState.Loading })
                assertEquals(null, malformedStore.value)
            } finally {
                malformed.close()
            }
        }

    @Test
    fun restoredSessionMustMatchTheExactClientAndDiscoveryConfiguration() =
        runBlocking {
            val issuer = "https://issuer.example"
            val original = testConfiguration(issuer)
            val store = MemoryStore().apply { value = storedTokenSet(issuer, "desktop-client").serialize(original) }
            val changed = original.copy(discoveryUrl = "https://other.example/.well-known/openid-configuration")
            val provider = OidcAuthProvider(changed, JvmOidcBrowserLauncher { false }, store)
            try {
                assertIs<AuthState.SignedOut>(provider.authState.first { it !is AuthState.Loading })
                assertEquals(null, store.value)
            } finally {
                provider.close()
            }
        }

    @Test
    fun signInUsesDiscoveryLoopbackPkceAndValidatedIdTokenThenRefreshes() =
        runBlocking {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val tokenRequests = mutableListOf<Map<String, String>>()
            val server = oidcServer(keyPair, tokenRequests)
            val issuer = "http://127.0.0.1:${server.address.port}"
            val rejectedStatus = CompletableFuture<Int>()
            var authorizationQuery: Map<String, String>? = null
            val launcher =
                JvmOidcBrowserLauncher { uri ->
                    val query = decodeForm(uri.rawQuery)
                    authorizationQuery = query
                    val redirect = checkNotNull(query["redirect_uri"])
                    val state = checkNotNull(query["state"])
                    val nonce = checkNotNull(query["nonce"])
                    currentNonce = nonce
                    Thread {
                        rejectedStatus.complete(callback("$redirect?state=wrong&code=attacker"))
                        callback("$redirect?state=${state.urlEncode()}&code=real-code&iss=${issuer.urlEncode()}")
                    }.start()
                    true
                }
            val store = MemoryStore()
            val provider =
                OidcAuthProvider(
                    configuration = testConfiguration(issuer),
                    browserLauncher = launcher,
                    sessionStore = store,
                )
            try {
                val signedIn = provider.signInWithOpenId()

                assertEquals("$issuer|subject-1", signedIn.getOrNull()?.uid)
                assertEquals("Ada Lovelace", signedIn.getOrNull()?.displayName)
                assertEquals("ada@example.test", signedIn.getOrNull()?.email)
                assertTrue(signedIn.getOrNull()?.isEmailVerified == true)
                assertIs<AuthState.SignedIn>(provider.authState.value)
                assertEquals(400, rejectedStatus.get(5, TimeUnit.SECONDS))
                val auth = assertNotNull(authorizationQuery)
                assertEquals("S256", auth["code_challenge_method"])
                assertTrue(auth["scope"].orEmpty().split(' ').containsAll(listOf("openid", "profile", "email")))
                assertTrue(auth["redirect_uri"].orEmpty().startsWith("http://127.0.0.1:"))
                val exchange = tokenRequests.first()
                assertEquals("real-code", exchange["code"])
                assertEquals(auth["redirect_uri"], exchange["redirect_uri"])
                assertEquals(auth["code_challenge"], checkNotNull(exchange["code_verifier"]).sha256Base64Url())
                assertFalse("client_secret" in exchange)
                val refreshed = provider.currentSession(forceRefresh = true).getOrNull()!!
                assertEquals("access-two", refreshed.accessToken)
                assertEquals("refresh-one", refreshed.refreshToken)
                assertFalse("client_secret" in tokenRequests.last())

                assertTrue(provider.signOut().isSuccess)
                assertIs<AuthState.SignedOut>(provider.authState.value)
                assertEquals(null, store.value)
            } finally {
                provider.close()
                server.stop(0)
            }
        }

    @Test
    fun nonceMismatchRejectsTheIdentityAndDoesNotPersistIt() =
        runBlocking {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val server = oidcServer(keyPair, mutableListOf(), forceNonce = "wrong-nonce")
            val issuer = "http://127.0.0.1:${server.address.port}"
            val store = MemoryStore()
            val provider = OidcAuthProvider(testConfiguration(issuer), successfulLauncher(), store)
            try {
                val result = provider.signInWithOpenId()

                assertIs<AuthError.InvalidCredentials>((result as AuthResult.Failure).error)
                assertEquals(null, store.value)
                assertIs<AuthState.SignedOut>(provider.authState.value)
                Unit
            } finally {
                provider.close()
                server.stop(0)
            }
        }

    @Test
    fun invalidGrantDuringRefreshClearsTheLocalSession() =
        runBlocking {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val server = oidcServer(keyPair, mutableListOf(), rejectRefresh = true)
            val issuer = "http://127.0.0.1:${server.address.port}"
            val provider = OidcAuthProvider(testConfiguration(issuer), successfulLauncher(), MemoryStore())
            try {
                assertTrue(provider.signInWithOpenId().isSuccess)

                val result = provider.currentSession(forceRefresh = true)

                assertIs<AuthError.InvalidCredentials>((result as AuthResult.Failure).error)
                assertIs<AuthState.SignedOut>(provider.authState.value)
                Unit
            } finally {
                provider.close()
                server.stop(0)
            }
        }

    @Test
    fun refreshCannotSwitchTheAuthenticatedSubject() =
        runBlocking {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            val server = oidcServer(keyPair, mutableListOf(), switchSubjectOnRefresh = true)
            val issuer = "http://127.0.0.1:${server.address.port}"
            val provider = OidcAuthProvider(testConfiguration(issuer), successfulLauncher(), MemoryStore())
            try {
                assertTrue(provider.signInWithOpenId().isSuccess)

                val result = provider.currentSession(forceRefresh = true)

                assertIs<AuthError.InvalidCredentials>((result as AuthResult.Failure).error)
                assertIs<AuthState.SignedOut>(provider.authState.value)
                Unit
            } finally {
                provider.close()
                server.stop(0)
            }
        }

    @Test
    fun discoveryBrowserFailureAndTimeoutAreTyped() =
        runBlocking {
            val blocked =
                OidcAuthProvider(
                    testConfiguration("http://127.0.0.1:1"),
                    JvmOidcBrowserLauncher { false },
                    MemoryStore(),
                )
            val blockedResult = blocked.signInWithOpenId()
            assertIs<AuthError.Network>((blockedResult as AuthResult.Failure).error)
            blocked.close()

            // Browser launch typing itself is covered without requiring discovery to fail first.
            val flow =
                JvmOidcBrowserFlow(
                    testConfiguration("http://127.0.0.1:1").copy(callbackTimeoutMillis = 20),
                    JvmOidcBrowserLauncher { false },
                    DefaultDispatcherProvider(),
                )
            val metadata =
                OidcMetadata(
                    issuer = "http://127.0.0.1:1",
                    authorizationEndpoint = URI("http://127.0.0.1:1/authorize"),
                    tokenEndpoint = URI("http://127.0.0.1:1/token"),
                    jwksUri = URI("http://127.0.0.1:1/jwks"),
                    supportedAlgorithms = setOf("RS256"),
                )
            val browserResult = runCatching { flow.authorize(metadata) }.exceptionOrNull() as OidcFailure
            assertIs<AuthError.PopupBlocked>(browserResult.error)
            flow.close()

            val timeoutFlow =
                JvmOidcBrowserFlow(
                    testConfiguration("http://127.0.0.1:1").copy(callbackTimeoutMillis = 20),
                    JvmOidcBrowserLauncher { true },
                    DefaultDispatcherProvider(),
                )
            val timeout = runCatching { timeoutFlow.authorize(metadata) }.exceptionOrNull() as OidcFailure
            assertIs<AuthError.Network>(timeout.error)
            assertEquals("timeout", timeout.error.providerCode)
            timeoutFlow.close()
        }

    private fun oidcServer(
        keyPair: KeyPair,
        requests: MutableList<Map<String, String>>,
        forceNonce: String? = null,
        rejectRefresh: Boolean = false,
        switchSubjectOnRefresh: Boolean = false,
    ): HttpServer =
        HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/.well-known/openid-configuration") { exchange ->
                val issuer = "http://127.0.0.1:${address.port}"
                exchange.respond(
                    200,
                    """{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks","id_token_signing_alg_values_supported":["RS256"]}""",
                )
            }
            createContext("/jwks") { exchange ->
                val publicKey = keyPair.public as RSAPublicKey
                exchange.respond(
                    200,
                    """{"keys":[{"kty":"RSA","kid":"key-1","use":"sig","alg":"RS256","n":"${publicKey.modulus.base64Url()}","e":"${publicKey.publicExponent.base64Url()}"}]}""",
                )
            }
            createContext("/token") { exchange ->
                val request = decodeForm(exchange.requestBody.bufferedReader().use { it.readText() })
                requests += request
                if (request["grant_type"] == "refresh_token") {
                    if (rejectRefresh) {
                        exchange.respond(400, """{"error":"invalid_grant","error_description":"expired refresh token"}""")
                    } else if (switchSubjectOnRefresh) {
                        val issuer = "http://127.0.0.1:${address.port}"
                        val idToken = signedIdToken(keyPair, issuer, currentNonce, subject = "different-subject")
                        exchange.respond(
                            200,
                            """{"access_token":"access-two","id_token":"$idToken","token_type":"Bearer","expires_in":3600}""",
                        )
                    } else {
                        exchange.respond(200, """{"access_token":"access-two","token_type":"Bearer","expires_in":3600}""")
                    }
                } else {
                    val issuer = "http://127.0.0.1:${address.port}"
                    val nonce = forceNonce ?: currentNonce
                    val idToken = signedIdToken(keyPair, issuer, nonce)
                    exchange.respond(
                        200,
                        """{"access_token":"access-one","refresh_token":"refresh-one","id_token":"$idToken","token_type":"Bearer","expires_in":3600}""",
                    )
                }
            }
            start()
        }

    private fun successfulLauncher(): JvmOidcBrowserLauncher =
        JvmOidcBrowserLauncher { uri ->
            val query = decodeForm(uri.rawQuery)
            currentNonce = checkNotNull(query["nonce"])
            val redirect = checkNotNull(query["redirect_uri"])
            val state = checkNotNull(query["state"])
            Thread { callback("$redirect?state=${state.urlEncode()}&code=real-code") }.start()
            true
        }

    private fun testConfiguration(issuer: String): OidcConfiguration =
        OidcConfiguration(
            clientId = "desktop-client",
            discoveryUrl = "$issuer/.well-known/openid-configuration",
            callbackTimeoutMillis = 1_000,
            allowInsecureHttpForTesting = true,
        )

    private class MemoryStore : JvmOidcSessionStore {
        var value: ByteArray? = null

        override suspend fun read(): ByteArray? = value

        override suspend fun write(value: ByteArray) {
            this.value = value.copyOf()
        }

        override suspend fun clear() {
            value = null
        }
    }

    private fun storedTokenSet(
        issuer: String,
        audience: String,
    ): OidcTokenSet {
        val now = Instant.now().epochSecond
        val claims =
            """{"iss":"$issuer","sub":"restored-subject","aud":"$audience","exp":${now + 3600},"iat":$now}"""
                .base64Url()
        val raw = "e30.$claims.signature"
        return OidcTokenSet(
            accessToken = "restored-access",
            refreshToken = "restored-refresh",
            idToken = decodeIdTokenWithoutVerification(raw),
            accessTokenExpiresAtEpochMillis = (now + 3600) * 1_000,
        )
    }

    private companion object {
        @Volatile
        var currentNonce: String = "unset"
    }
}

private fun signedIdToken(
    keyPair: KeyPair,
    issuer: String,
    nonce: String,
    subject: String = "subject-1",
): String {
    val now = Instant.now().epochSecond
    val header = """{"alg":"RS256","kid":"key-1","typ":"JWT"}""".base64Url()
    val claims =
        """{"iss":"$issuer","sub":"$subject","aud":"desktop-client","exp":${now + 3600},"iat":$now,"nonce":"$nonce","name":"Ada Lovelace","email":"ada@example.test","email_verified":true}"""
            .base64Url()
    val signingInput = "$header.$claims"
    val signature =
        Signature.getInstance("SHA256withRSA").run {
            initSign(keyPair.private)
            update(signingInput.toByteArray(StandardCharsets.US_ASCII))
            sign().base64Url()
        }
    return "$signingInput.$signature"
}

private fun callback(url: String): Int {
    val connection = URI(url).toURL().openConnection() as HttpURLConnection
    return try {
        connection.responseCode
    } finally {
        connection.disconnect()
    }
}

private fun decodeForm(value: String): Map<String, String> =
    value.split('&').filter(String::isNotBlank).associate { field ->
        val parts = field.split('=', limit = 2)
        parts[0].urlDecode() to parts.getOrElse(1) { "" }.urlDecode()
    }

private fun String.urlEncode(): String = java.net.URLEncoder.encode(this, StandardCharsets.UTF_8.name())

private fun String.urlDecode(): String = URLDecoder.decode(this, StandardCharsets.UTF_8.name())

private fun String.sha256Base64Url(): String =
    MessageDigest.getInstance("SHA-256").digest(toByteArray(StandardCharsets.US_ASCII)).base64Url()

private fun String.base64Url(): String = toByteArray(StandardCharsets.UTF_8).base64Url()

private fun ByteArray.base64Url(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

private fun java.math.BigInteger.base64Url(): String = toByteArray().dropWhile { it == 0.toByte() }.toByteArray().base64Url()

private fun HttpExchange.respond(
    status: Int,
    body: String,
) {
    val bytes = body.toByteArray(StandardCharsets.UTF_8)
    responseHeaders.set("Content-Type", "application/json")
    sendResponseHeaders(status, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}
