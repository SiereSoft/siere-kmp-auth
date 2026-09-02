package dev.siere.auth.firebase

import android.app.Application
import com.google.firebase.FirebasePlatform
import com.sun.net.httpserver.HttpServer
import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.FirebaseOptions
import dev.gitlive.firebase.auth.auth
import dev.gitlive.firebase.initialize
import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthUser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class JvmFirebaseAuthBrokerTest {
    @Test
    fun brokerAppleSignInAndPhoneLinkUseTheFirebaseSessionBridge() =
        runBlocking {
            val requests = LinkedBlockingQueue<Pair<String, String>>()
            val responses =
                LinkedBlockingQueue<String>().apply {
                    add(authResponse("apple-firebase-token", "apple.com"))
                    add(authResponse("phone-firebase-token", "phone"))
                }
            val server = authServer(requests, responses)
            FirebasePlatform.initializeFirebasePlatform(InMemoryFirebasePlatform())
            val app =
                Firebase.initialize(
                    Application(),
                    FirebaseOptions(
                        applicationId = "1:123456789:jvm:broker-test",
                        apiKey = "local-test-key",
                        projectId = "local-test-project",
                    ),
                )
            Firebase.auth.useEmulator("127.0.0.1", server.address.port)
            val broker = RecordingBroker()
            val provider = FirebaseAuthProvider(broker)

            try {
                val invalidPhone = assertIs<AuthResult.Failure>(provider.startPhoneSignIn("555-0123"))
                assertIs<AuthError.InvalidPhoneNumber>(invalidPhone.error)
                assertEquals(null, broker.phoneOperation)

                val appleResult = provider.signInWithApple()
                val appleResultValue =
                    assertIs<AuthResult.Success<*>>(
                        appleResult,
                        "result=$appleResult, requestCount=${requests.size}",
                    ).value
                val apple = assertIs<AuthUser>(appleResultValue)
                assertEquals(JvmAuthOperation.SIGN_IN, broker.appleOperation)
                assertEquals("broker-user", apple.uid)
                assertEquals(setOf("apple.com"), apple.providerIds.toSet())
                val appleRequest = requests.take()
                assertTrue(appleRequest.first.endsWith("accounts:signInWithIdp"))
                assertTrue(appleRequest.second.contains("providerId=apple.com"))
                assertTrue(appleRequest.second.contains("apple-raw-nonce"))

                val session =
                    assertIs<AuthResult.Success<*>>(provider.startPhoneLinking("+15555550123"))
                        .value as dev.siere.auth.PhoneVerificationSession
                assertEquals(JvmAuthOperation.LINK, broker.phoneOperation)
                val linked = assertIs<AuthUser>(assertIs<AuthResult.Success<*>>(session.confirm("654321")).value)
                assertEquals("broker-user", linked.uid)
                assertEquals(setOf("apple.com", "phone"), linked.providerIds.toSet())
                val phoneRequest = requests.take()
                assertTrue(phoneRequest.first.endsWith("accounts:signInWithPhoneNumber"))
                assertTrue(phoneRequest.second.contains("broker-verification-id"))
                assertTrue(phoneRequest.second.contains("654321"))
                assertTrue(phoneRequest.second.contains("apple-firebase-token"))
            } finally {
                provider.signOut()
                provider.close()
                app.delete()
                server.stop(0)
            }
            assertTrue(broker.closed)
        }

    @Test
    fun brokerCredentialsRedactEverySensitiveValue() {
        assertFalse(JvmAppleCredential("apple-token", "apple-nonce").toString().contains("apple-token"))
        assertFalse(JvmAppleCredential("apple-token", "apple-nonce").toString().contains("apple-nonce"))
        assertFalse(JvmPhoneChallenge("challenge-secret").toString().contains("challenge-secret"))
        assertFalse(JvmPhoneCredential("verification-secret", "123456").toString().contains("123456"))
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
          "localId": "broker-user",
          "idToken": "$idToken",
          "refreshToken": "refresh-token",
          "expiresIn": "3600",
          "email": "broker@example.com",
          "emailVerified": true,
          "providerId": "$providerId"
        }
        """.trimIndent()

    private class RecordingBroker : JvmFirebaseAuthBroker {
        var appleOperation: JvmAuthOperation? = null
        var phoneOperation: JvmAuthOperation? = null
        var closed = false

        override suspend fun authorizeApple(operation: JvmAuthOperation): JvmAppleCredential {
            appleOperation = operation
            return JvmAppleCredential("apple-id-token", "apple-raw-nonce")
        }

        override suspend fun startPhoneVerification(
            phoneNumber: String,
            operation: JvmAuthOperation,
        ): JvmPhoneChallenge {
            assertEquals("+15555550123", phoneNumber)
            phoneOperation = operation
            return JvmPhoneChallenge("opaque-challenge")
        }

        override suspend fun completePhoneVerification(
            challenge: JvmPhoneChallenge,
            smsCode: String,
        ): JvmPhoneCredential {
            assertEquals("opaque-challenge", challenge.handle)
            assertEquals("654321", smsCode)
            return JvmPhoneCredential("broker-verification-id", smsCode)
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
