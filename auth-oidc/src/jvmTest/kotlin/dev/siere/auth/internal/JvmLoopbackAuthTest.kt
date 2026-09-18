package dev.siere.auth.internal

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import java.net.HttpURLConnection
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JvmLoopbackAuthTest {
    @Test
    fun pkceValuesAreRandomAndChallengeMatchesVerifier() {
        val first = newJvmPkceRequest()
        val second = newJvmPkceRequest()

        assertNotEquals(first.state, second.state)
        assertNotEquals(first.verifier, second.verifier)
        assertEquals(first.verifier.sha256Base64Url(), first.challenge)
    }

    @Test
    fun callbackRequiresExactStateHostMethodAndUniqueParameters() =
        runBlocking {
            val callback = newCallback()
            callback.start()
            val result = async(Dispatchers.IO) { callback.await(5_000) }
            val port = callback.redirectUri.port

            assertEquals(400, rawRequest(port, "GET", "/callback?state=wrong&code=x").status)
            assertEquals(400, rawRequest(port, "POST", "/callback?state=expected&code=x").status)
            assertEquals(404, rawRequest(port, "GET", "/wrong?state=expected&code=x").status)
            assertEquals(400, rawRequest(port, "GET", "/callback?state=expected&state=expected&code=x").status)
            assertEquals(400, rawRequest(port, "GET", "/callback?state=%ZZ&code=x").status)
            assertEquals(
                400,
                rawRequest(port, "GET", "/callback?state=expected&code=x", host = "localhost:$port").status,
            )

            val accepted = rawRequest(port, "GET", "/callback?state=expected&code=real")
            assertEquals(200, accepted.status)
            assertEquals("no-store", accepted.headers["cache-control"])
            assertEquals("no-cache", accepted.headers["pragma"])
            assertEquals("no-referrer", accepted.headers["referrer-policy"])
            assertEquals("nosniff", accepted.headers["x-content-type-options"])
            assertEquals("default-src 'none'; frame-ancestors 'none'", accepted.headers["content-security-policy"])
            assertEquals("real", result.await()?.get("code"))
        }

    @Test
    fun callbackRejectsExcessiveQueryParameters() {
        val callback = newCallback()
        callback.start()
        try {
            val excessive = (0..32).joinToString("&") { "value$it=x" }

            assertEquals(
                400,
                rawRequest(callback.redirectUri.port, "GET", "/callback?state=expected&$excessive").status,
            )
        } finally {
            callback.close()
        }
    }

    @Test
    fun timeoutAndCancellationCloseTheLoopbackListener() =
        runBlocking {
            val timedOut = newCallback()
            timedOut.start()
            val timedOutPort = timedOut.redirectUri.port
            assertNull(timedOut.await(20))
            assertFalse(canConnect(timedOutPort))

            val cancelled = newCallback()
            cancelled.start()
            val cancelledPort = cancelled.redirectUri.port
            val entered = CountDownLatch(1)
            val waiter =
                async(Dispatchers.IO) {
                    entered.countDown()
                    cancelled.await(5_000)
                }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            waiter.cancelAndJoin()
            assertFalse(canConnect(cancelledPort))
        }

    private fun newCallback(): JvmLoopbackCallback = JvmLoopbackCallback("expected", "Success", "Failure")
}

private data class RawResponse(
    val status: Int,
    val headers: Map<String, String>,
)

private fun rawRequest(
    port: Int,
    method: String,
    path: String,
    host: String = "127.0.0.1:$port",
): RawResponse =
    Socket("127.0.0.1", port).use { socket ->
        socket.getOutputStream().bufferedWriter(StandardCharsets.US_ASCII).use { writer ->
            writer.write("$method $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n")
            writer.flush()
            socket.getInputStream().bufferedReader(StandardCharsets.US_ASCII).use { reader ->
                val status = reader.readLine().split(' ')[1].toInt()
                val headers =
                    generateSequence(reader::readLine)
                        .takeWhile(String::isNotEmpty)
                        .associate { line ->
                            val (name, value) = line.split(':', limit = 2)
                            name.lowercase() to value.trim()
                        }
                RawResponse(status, headers)
            }
        }
    }

private fun canConnect(port: Int): Boolean =
    runCatching {
        val connection =
            java.net
                .URI("http://127.0.0.1:$port/callback")
                .toURL()
                .openConnection() as HttpURLConnection
        connection.connectTimeout = 100
        connection.readTimeout = 100
        connection.responseCode
        connection.disconnect()
    }.isSuccess

private fun String.sha256Base64Url(): String =
    java.security.MessageDigest
        .getInstance("SHA-256")
        .digest(toByteArray(StandardCharsets.US_ASCII))
        .let {
            java.util.Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(it)
        }
