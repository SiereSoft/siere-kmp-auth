@file:Suppress("MagicNumber")

package dev.siere.auth.internal

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

internal data class JvmPkceRequest(
    val state: String,
    val verifier: String,
    val challenge: String,
)

internal fun newJvmPkceRequest(): JvmPkceRequest {
    val random = SecureRandom()
    val state = random.bytes(32)
    val verifier = random.bytes(64)
    return JvmPkceRequest(state, verifier, verifier.sha256Base64Url())
}

internal fun newJvmSecureRandomValue(byteCount: Int): String = SecureRandom().bytes(byteCount)

internal class JvmLoopbackCallback(
    private val expectedState: String,
    private val successMessage: String,
    private val failureMessage: String,
) : AutoCloseable {
    private val completion = CompletableDeferred<Map<String, String>>()
    private val started = AtomicBoolean(false)
    private val stopped = AtomicBoolean(false)
    private val claimed = AtomicBoolean(false)
    private val server = HttpServer.create(InetSocketAddress(InetAddress.getByName(LOOPBACK_HOST), 0), 0)

    val redirectUri: URI get() = URI("http://$LOOPBACK_HOST:${server.address.port}$CALLBACK_PATH")

    init {
        server.createContext(CALLBACK_PATH, ::handle)
    }

    fun start() {
        check(started.compareAndSet(false, true)) { "Loopback callback server was already started" }
        server.start()
    }

    suspend fun await(timeoutMillis: Long): Map<String, String>? =
        try {
            withTimeoutOrNull(timeoutMillis) { completion.await() }
        } finally {
            close()
        }

    fun cancel(cause: Throwable) {
        completion.completeExceptionally(cause)
        close()
    }

    override fun close() {
        if (stopped.compareAndSet(false, true)) server.stop(0)
    }

    private fun handle(exchange: HttpExchange) {
        val parameters =
            exchange.requestURI.rawQuery
                ?.takeIf { it.length <= MAX_QUERY_CHARACTERS }
                ?.let { query -> runCatching { parseUniqueQuery(query) }.getOrNull() }
        val expectedHost = "$LOOPBACK_HOST:${server.address.port}"
        val valid =
            exchange.requestMethod == "GET" &&
                exchange.requestURI.path == CALLBACK_PATH &&
                exchange.requestHeaders.getFirst("Host") == expectedHost &&
                parameters?.get("state")?.constantTimeEquals(expectedState) == true
        val accepted = valid && claimed.compareAndSet(false, true)
        try {
            exchange.respond(if (accepted) 200 else 400, if (accepted) successMessage else failureMessage)
        } finally {
            if (accepted) completion.complete(checkNotNull(parameters))
        }
    }
}

private fun parseUniqueQuery(query: String): Map<String, String>? {
    val pairs =
        query
            .split('&')
            .filter(String::isNotBlank)
            .takeIf { it.size <= MAX_QUERY_PARAMETERS }
            ?: return null
    val decoded =
        pairs
            .map { field ->
                val parts = field.split('=', limit = 2)
                parts[0].urlDecode() to parts.getOrElse(1) { "" }.urlDecode()
            }
    return decoded.toMap().takeIf { result ->
        result.size == decoded.size &&
            result.keys.none { it.isBlank() || it.length > MAX_PARAMETER_NAME_CHARACTERS } &&
            result.values.none { it.length > MAX_PARAMETER_VALUE_CHARACTERS }
    }
}

private fun HttpExchange.respond(
    status: Int,
    message: String,
) {
    val bytes = message.toByteArray(StandardCharsets.UTF_8)
    responseHeaders.set("Content-Type", "text/plain; charset=utf-8")
    responseHeaders.set("Cache-Control", "no-store")
    responseHeaders.set("Pragma", "no-cache")
    responseHeaders.set("Referrer-Policy", "no-referrer")
    responseHeaders.set("X-Content-Type-Options", "nosniff")
    responseHeaders.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    sendResponseHeaders(status, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}

private fun SecureRandom.bytes(size: Int): String =
    ByteArray(size).also(::nextBytes).let(Base64.getUrlEncoder().withoutPadding()::encodeToString)

private fun String.sha256Base64Url(): String =
    MessageDigest
        .getInstance("SHA-256")
        .digest(toByteArray(StandardCharsets.US_ASCII))
        .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }

private fun String.constantTimeEquals(expected: String): Boolean =
    MessageDigest.isEqual(
        toByteArray(StandardCharsets.US_ASCII),
        expected.toByteArray(StandardCharsets.US_ASCII),
    )

private fun String.urlDecode(): String = URLDecoder.decode(this, StandardCharsets.UTF_8.name())

private const val LOOPBACK_HOST = "127.0.0.1"
private const val CALLBACK_PATH = "/callback"
private const val MAX_QUERY_CHARACTERS = 16 * 1024
private const val MAX_QUERY_PARAMETERS = 32
private const val MAX_PARAMETER_NAME_CHARACTERS = 256
private const val MAX_PARAMETER_VALUE_CHARACTERS = 8 * 1024
