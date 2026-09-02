package dev.siere.auth.firebase

import android.app.Application
import com.google.firebase.FirebasePlatform
import com.sun.net.httpserver.HttpServer
import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.FirebaseOptions
import dev.gitlive.firebase.auth.auth
import dev.gitlive.firebase.initialize
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthUser
import dev.siere.auth.DefaultDispatcherProvider
import dev.siere.auth.SiereAuth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class JvmGoogleIntegrationTest {
    @Test
    fun anonymousUserLinksGoogleThroughSiereAuth() =
        runBlocking {
            val requests = LinkedBlockingQueue<Pair<String, String>>()
            val responses =
                LinkedBlockingQueue<String>().apply {
                    add(authResponse("anonymous-firebase-token", "anonymous"))
                    add(authResponse("linked-firebase-token", "google.com"))
                }
            val server = authServer(requests, responses)
            FirebasePlatform.initializeFirebasePlatform(InMemoryFirebasePlatform())
            val app =
                Firebase.initialize(
                    Application(),
                    FirebaseOptions(
                        applicationId = "1:123456789:jvm:google-link-test",
                        apiKey = "local-test-key",
                        projectId = "local-test-project",
                    ),
                )
            Firebase.auth.useEmulator("127.0.0.1", server.address.port)
            val oauthClient = RecordingGoogleOAuthClient()
            val auth =
                SiereAuth(
                    JvmFirebaseAuthProvider(
                        oauthClient = oauthClient,
                        authBroker = null,
                        dispatcherProvider = DefaultDispatcherProvider(),
                    ),
                )

            try {
                val anonymous = assertIs<AuthUser>(assertIs<AuthResult.Success<*>>(auth.signInAnonymously()).value)
                assertTrue(anonymous.isAnonymous)

                val linked = assertIs<AuthUser>(assertIs<AuthResult.Success<*>>(auth.linkWithGoogle()).value)

                assertEquals("google-link-user", linked.uid)
                assertEquals(setOf("anonymous", "google.com"), linked.providerIds.toSet())
                assertEquals(1, oauthClient.authorizationCount)
                val anonymousRequest = requests.take()
                assertTrue(anonymousRequest.first.endsWith("accounts:signUp"))
                val linkRequest = requests.take()
                assertTrue(linkRequest.first.endsWith("accounts:signInWithIdp"))
                assertTrue(linkRequest.second.contains("anonymous-firebase-token"))
                assertTrue(linkRequest.second.contains("providerId=google.com"))
                assertTrue(linkRequest.second.contains("google-id-token"))
                assertTrue(linkRequest.second.contains("google-access-token"))
            } finally {
                auth.signOut()
                auth.close()
                app.delete()
                server.stop(0)
            }
            assertTrue(oauthClient.closed)
        }

    private fun authServer(
        requests: LinkedBlockingQueue<Pair<String, String>>,
        responses: LinkedBlockingQueue<String>,
    ): HttpServer =
        HttpServer
            .create(InetSocketAddress("127.0.0.1", 0), 0)
            .apply {
                createContext("/") { exchange ->
                    val requestBody = exchange.requestBody.bufferedReader().use { it.readText() }
                    requests.add(exchange.requestURI.path to requestBody)
                    val bytes = responses.take().toByteArray()
                    exchange.responseHeaders.set("Content-Type", "application/json")
                    exchange.sendResponseHeaders(200, bytes.size.toLong())
                    exchange.responseBody.use { it.write(bytes) }
                }
                start()
            }

    private fun authResponse(
        idToken: String,
        providerId: String,
    ): String =
        """
        {
          "localId": "google-link-user",
          "idToken": "$idToken",
          "refreshToken": "refresh-token",
          "expiresIn": "3600",
          "email": "linked@example.com",
          "emailVerified": true,
          "providerId": "$providerId"
        }
        """.trimIndent()

    private class RecordingGoogleOAuthClient : JvmGoogleOAuthClient {
        var authorizationCount = 0
        var closed = false

        override suspend fun authorize(): JvmGoogleTokens {
            authorizationCount += 1
            return JvmGoogleTokens("google-id-token", "google-access-token")
        }

        override fun close() {
            closed = true
        }
    }

    private class InMemoryFirebasePlatform : FirebasePlatform() {
        private val values = mutableMapOf<String, String>()

        override val mainDispatcher = Dispatchers.Default

        override fun store(
            key: String,
            value: String,
        ) {
            values[key] = value
        }

        override fun retrieve(key: String): String? = values[key]

        override fun clear(key: String) {
            values.remove(key)
        }

        override fun log(msg: String): Unit = Unit

        override fun getDatabasePath(name: String): File = File("./build/$name")
    }
}
