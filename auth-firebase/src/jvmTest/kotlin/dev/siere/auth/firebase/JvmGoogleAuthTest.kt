package dev.siere.auth.firebase

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import dev.siere.auth.DefaultDispatcherProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JvmGoogleAuthTest {
    @Test
    fun authorizationUsesLoopbackStateAndPkceThenExchangesTokens() =
        runBlocking {
            val tokenRequestBody = CompletableFuture<String>()
            val tokenServer = tokenServer(tokenRequestBody)
            val rejectedCallbackStatus = CompletableFuture<Int>()
            var authorizationUri: URI? = null
            val launcher =
                JvmBrowserLauncher { uri ->
                    authorizationUri = uri
                    val query = decodeForm(uri.rawQuery)
                    val redirectUri = checkNotNull(query["redirect_uri"])
                    val state = checkNotNull(query["state"])
                    Thread {
                        rejectedCallbackStatus.complete(
                            callback("$redirectUri?state=wrong-state&code=attacker-code"),
                        )
                        callback("$redirectUri?state=${state.urlEncode()}&code=real-code")
                    }.start()
                    true
                }
            val config = JvmGoogleAuthConfig("desktop-client", "desktop-secret")
            val client =
                DefaultJvmGoogleOAuthClient(
                    config = config,
                    browserLauncher = launcher,
                    dispatcherProvider = DefaultDispatcherProvider(),
                    authorizationEndpoint = URI("https://accounts.example.test/authorize"),
                    tokenEndpoint = URI("http://127.0.0.1:${tokenServer.address.port}/token"),
                )

            try {
                val tokens = client.authorize()

                assertEquals("firebase-google-id-token", tokens.idToken)
                assertEquals("google-access-token", tokens.accessToken)
                assertEquals(400, rejectedCallbackStatus.get(5, TimeUnit.SECONDS))
                val authQuery = decodeForm(assertNotNull(authorizationUri).rawQuery)
                assertEquals("S256", authQuery["code_challenge_method"])
                assertEquals("openid email profile", authQuery["scope"])
                assertTrue(checkNotNull(authQuery["redirect_uri"]).startsWith("http://127.0.0.1:"))

                val tokenForm = decodeForm(tokenRequestBody.get(5, TimeUnit.SECONDS))
                assertEquals("desktop-client", tokenForm["client_id"])
                assertEquals("desktop-secret", tokenForm["client_secret"])
                assertEquals("real-code", tokenForm["code"])
                assertEquals(authQuery["redirect_uri"], tokenForm["redirect_uri"])
                assertEquals(
                    authQuery["code_challenge"],
                    checkNotNull(tokenForm["code_verifier"]).sha256Base64Url(),
                )
                assertFalse(config.toString().contains("desktop-secret"))
            } finally {
                client.close()
                tokenServer.stop(0)
            }
        }

    @Test
    fun publicClientOmitsClientSecretFromTokenExchange() =
        runBlocking {
            val tokenRequestBody = CompletableFuture<String>()
            val tokenServer = tokenServer(tokenRequestBody)
            val client =
                DefaultJvmGoogleOAuthClient(
                    config = JvmGoogleAuthConfig("public-desktop-client"),
                    browserLauncher = successfulLauncher(),
                    dispatcherProvider = DefaultDispatcherProvider(),
                    authorizationEndpoint = URI("https://accounts.example.test/authorize"),
                    tokenEndpoint = URI("http://127.0.0.1:${tokenServer.address.port}/token"),
                )

            try {
                client.authorize()

                val tokenForm = decodeForm(tokenRequestBody.get(5, TimeUnit.SECONDS))
                assertEquals("public-desktop-client", tokenForm["client_id"])
                assertFalse("client_secret" in tokenForm)
                assertTrue(client.toString().isNotEmpty())
            } finally {
                client.close()
                tokenServer.stop(0)
            }
        }

    @Test
    fun malformedCallbackIsRejectedWithoutEndingAuthorization() =
        runBlocking {
            val tokenRequestBody = CompletableFuture<String>()
            val tokenServer = tokenServer(tokenRequestBody)
            val malformedCallbackStatus = CompletableFuture<Int>()
            val client =
                DefaultJvmGoogleOAuthClient(
                    config = JvmGoogleAuthConfig("public-desktop-client"),
                    browserLauncher =
                        JvmBrowserLauncher { uri ->
                            val query = decodeForm(uri.rawQuery)
                            val redirectUri = URI(checkNotNull(query["redirect_uri"]))
                            val state = checkNotNull(query["state"])
                            Thread {
                                malformedCallbackStatus.complete(
                                    rawCallback(redirectUri.port, "/callback?state=%ZZ&code=invalid"),
                                )
                                callback("$redirectUri?state=${state.urlEncode()}&code=real-code")
                            }.start()
                            true
                        },
                    dispatcherProvider = DefaultDispatcherProvider(),
                    authorizationEndpoint = URI("https://accounts.example.test/authorize"),
                    tokenEndpoint = URI("http://127.0.0.1:${tokenServer.address.port}/token"),
                )

            try {
                val tokens = client.authorize()

                assertEquals(400, malformedCallbackStatus.get(5, TimeUnit.SECONDS))
                assertEquals("firebase-google-id-token", tokens.idToken)
            } finally {
                client.close()
                tokenServer.stop(0)
            }
        }

    @Test
    fun accessDeniedIsReportedAsUserCancellation() {
        val client =
            DefaultJvmGoogleOAuthClient(
                config = JvmGoogleAuthConfig("desktop-client"),
                browserLauncher = callbackLauncher("error=access_denied"),
                dispatcherProvider = DefaultDispatcherProvider(),
            )

        val failure = assertFailsWith<IllegalStateException> { runBlocking { client.authorize() } }

        assertTrue(failure.message.orEmpty().contains("auth/user-cancelled"))
        client.close()
    }

    @Test
    fun callbackTimeoutIsReportedAsNetworkTimeout() {
        val client =
            DefaultJvmGoogleOAuthClient(
                config = JvmGoogleAuthConfig("desktop-client", callbackTimeoutMillis = 25),
                browserLauncher = JvmBrowserLauncher { true },
                dispatcherProvider = DefaultDispatcherProvider(),
            )

        val failure = assertFailsWith<IllegalStateException> { runBlocking { client.authorize() } }

        assertTrue(failure.message.orEmpty().contains("auth/timeout"))
        client.close()
    }

    @Test
    fun callerCancellationStopsAuthorizationAndReleasesTheClient() =
        runBlocking {
            val launched = CountDownLatch(1)
            val client =
                DefaultJvmGoogleOAuthClient(
                    config = JvmGoogleAuthConfig("desktop-client", callbackTimeoutMillis = 25),
                    browserLauncher = JvmBrowserLauncher { launched.countDown().let { true } },
                    dispatcherProvider = DefaultDispatcherProvider(),
                )
            val authorization = async(Dispatchers.Default) { client.authorize() }
            assertTrue(launched.await(5, TimeUnit.SECONDS))

            authorization.cancelAndJoin()

            assertTrue(authorization.isCancelled)
            val retryFailure = assertFailsWith<IllegalStateException> { client.authorize() }
            assertTrue(retryFailure.message.orEmpty().contains("auth/timeout"))
            client.close()
        }

    @Test
    fun closeTerminatesAnActiveAuthorization() =
        runBlocking {
            val launched = CountDownLatch(1)
            val client =
                DefaultJvmGoogleOAuthClient(
                    config = JvmGoogleAuthConfig("desktop-client", "desktop-secret"),
                    browserLauncher = JvmBrowserLauncher { launched.countDown().let { true } },
                    dispatcherProvider = DefaultDispatcherProvider(),
                )
            val result = async(Dispatchers.Default) { runCatching { client.authorize() } }
            assertTrue(launched.await(5, TimeUnit.SECONDS))

            client.close()

            val failure = assertNotNull(result.await().exceptionOrNull())
            assertTrue(failure.message.orEmpty().contains("auth/user-cancelled"))
        }

    @Test
    fun browserLaunchFailureIsTypedForFirebaseMapping() {
        val client =
            DefaultJvmGoogleOAuthClient(
                config = JvmGoogleAuthConfig("desktop-client", "desktop-secret"),
                browserLauncher = JvmBrowserLauncher { false },
                dispatcherProvider = DefaultDispatcherProvider(),
            )

        val failure = assertFailsWith<IllegalStateException> { runBlocking { client.authorize() } }

        assertTrue(failure.message.orEmpty().contains("auth/popup-blocked"))
        client.close()
    }

    private fun tokenServer(requestBody: CompletableFuture<String>): HttpServer =
        HttpServer
            .create(InetSocketAddress("127.0.0.1", 0), 0)
            .apply {
                createContext("/token") { exchange ->
                    requestBody.complete(exchange.requestBody.bufferedReader().use { it.readText() })
                    exchange.respond(
                        200,
                        """{"id_token":"firebase-google-id-token","access_token":"google-access-token"}""",
                    )
                }
                start()
            }

    private fun successfulLauncher(): JvmBrowserLauncher = callbackLauncher("code=real-code")

    private fun callbackLauncher(result: String): JvmBrowserLauncher =
        JvmBrowserLauncher { uri ->
            val query = decodeForm(uri.rawQuery)
            val redirectUri = checkNotNull(query["redirect_uri"])
            val state = checkNotNull(query["state"])
            Thread { callback("$redirectUri?state=${state.urlEncode()}&$result") }.start()
            true
        }

    private fun callback(url: String): Int {
        val connection = URI(url).toURL().openConnection() as HttpURLConnection
        return try {
            connection.responseCode
        } finally {
            connection.disconnect()
        }
    }

    private fun rawCallback(
        port: Int,
        path: String,
    ): Int =
        Socket("127.0.0.1", port).use { socket ->
            socket.getOutputStream().bufferedWriter(StandardCharsets.US_ASCII).use { writer ->
                writer.write("GET $path HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n")
                writer.flush()
                socket.getInputStream().bufferedReader(StandardCharsets.US_ASCII).use { reader ->
                    reader.readLine().split(' ')[1].toInt()
                }
            }
        }

    private fun decodeForm(value: String): Map<String, String> =
        value
            .split('&')
            .associate { field ->
                val parts = field.split('=', limit = 2)
                parts[0].urlDecode() to parts.getOrElse(1) { "" }.urlDecode()
            }

    private fun String.urlEncode(): String = java.net.URLEncoder.encode(this, StandardCharsets.UTF_8.name())

    private fun String.urlDecode(): String = URLDecoder.decode(this, StandardCharsets.UTF_8.name())

    private fun String.sha256Base64Url(): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(toByteArray(StandardCharsets.US_ASCII))
            .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }

    private fun HttpExchange.respond(
        status: Int,
        body: String,
    ) {
        val bytes = body.toByteArray(StandardCharsets.UTF_8)
        sendResponseHeaders(status, bytes.size.toLong())
        responseBody.use { it.write(bytes) }
    }
}
