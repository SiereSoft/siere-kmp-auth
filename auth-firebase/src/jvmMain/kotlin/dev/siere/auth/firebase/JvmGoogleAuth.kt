package dev.siere.auth.firebase

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import dev.siere.auth.DispatcherProvider
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.awt.Desktop
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val DEFAULT_GOOGLE_CALLBACK_TIMEOUT_MILLIS = 120_000L
private const val CALLBACK_PATH = "/callback"
private const val STATE_BYTE_COUNT = 32
private const val VERIFIER_BYTE_COUNT = 64
private const val HTTP_OK = 200
private const val HTTP_BAD_REQUEST = 400
private const val HTTP_SUCCESS_LAST = 299
private const val HTTP_TIMEOUT_MILLIS = 30_000

/**
 * Consumer-owned Google Desktop OAuth configuration used by JVM browser sign-in.
 *
 * [clientSecret] is optional for public clients. It exists for controlled JVM deployments whose
 * OAuth client requires authentication; a value embedded in a distributed Desktop application is
 * not confidential. PKCE is always used.
 */
public class JvmGoogleAuthConfig(
    public val clientId: String,
    clientSecret: String? = null,
    public val scopes: List<String> = listOf("openid", "email", "profile"),
    public val callbackTimeoutMillis: Long = DEFAULT_GOOGLE_CALLBACK_TIMEOUT_MILLIS,
) {
    internal val clientSecret: String? = clientSecret

    init {
        require(clientId.isNotBlank()) { "Google OAuth client ID must not be blank" }
        require(clientSecret == null || clientSecret.isNotBlank()) {
            "Google OAuth client secret must be null or non-blank"
        }
        require(scopes.isNotEmpty() && scopes.none(String::isBlank)) {
            "Google OAuth scopes must not be empty or blank"
        }
        require(callbackTimeoutMillis > 0) { "Google OAuth callback timeout must be positive" }
    }

    override fun toString(): String =
        "JvmGoogleAuthConfig(clientId=$clientId, " +
            "clientSecret=${if (clientSecret == null) "<not supplied>" else "<redacted>"}, scopes=$scopes, " +
            "callbackTimeoutMillis=$callbackTimeoutMillis)"
}

/** Opens the consumer's system browser for a JVM OAuth authorization request. */
public fun interface JvmBrowserLauncher {
    /** Returns true only when the authorization URI was handed to a browser. */
    public fun open(uri: URI): Boolean
}

/** Default launcher backed by [Desktop.browse]. */
public object SystemJvmBrowserLauncher : JvmBrowserLauncher {
    override fun open(uri: URI): Boolean =
        runCatching {
            check(Desktop.isDesktopSupported())
            val desktop = Desktop.getDesktop()
            check(desktop.isSupported(Desktop.Action.BROWSE))
            desktop.browse(uri)
        }.isSuccess
}

internal data class JvmGoogleTokens(
    val idToken: String,
    val accessToken: String?,
)

internal interface JvmGoogleOAuthClient : AutoCloseable {
    suspend fun authorize(): JvmGoogleTokens
}

internal class DefaultJvmGoogleOAuthClient(
    private val config: JvmGoogleAuthConfig,
    private val browserLauncher: JvmBrowserLauncher,
    private val dispatcherProvider: DispatcherProvider,
    private val authorizationEndpoint: URI = URI("https://accounts.google.com/o/oauth2/v2/auth"),
    private val tokenEndpoint: URI = URI("https://oauth2.googleapis.com/token"),
) : JvmGoogleOAuthClient {
    private val random = SecureRandom()
    private val operationMutex = Mutex()
    private val lifecycleLock = Any()
    private val closed = AtomicBoolean(false)
    private val activeServer = AtomicReference<HttpServer?>()
    private val activeCallback = AtomicReference<CompletableDeferred<Map<String, String>>?>()

    override suspend fun authorize(): JvmGoogleTokens =
        operationMutex.withLock {
            checkOpen()
            val callback = CompletableDeferred<Map<String, String>>()
            val state = randomUrlSafe(STATE_BYTE_COUNT)
            val verifier = randomUrlSafe(VERIFIER_BYTE_COUNT)
            val challenge = verifier.sha256Base64Url()
            val server = createLoopbackServer(state, callback)
            val redirectUri = URI("http://127.0.0.1:${server.address.port}$CALLBACK_PATH")

            try {
                synchronized(lifecycleLock) {
                    checkOpen()
                    activeServer.set(server)
                    activeCallback.set(callback)
                    server.start()
                }
                val authorizationUri =
                    URI(
                        "$authorizationEndpoint?" +
                            form(
                                listOf(
                                    "client_id" to config.clientId,
                                    "redirect_uri" to redirectUri.toString(),
                                    "response_type" to "code",
                                    "scope" to config.scopes.joinToString(" "),
                                    "code_challenge" to challenge,
                                    "code_challenge_method" to "S256",
                                    "state" to state,
                                    "prompt" to "select_account",
                                ),
                            ),
                    )
                val opened = withContext(dispatcherProvider.io) { browserLauncher.open(authorizationUri) }
                if (!opened) throw JvmOAuthException("auth/popup-blocked: the system browser could not be opened")

                val parameters =
                    withTimeoutOrNull(config.callbackTimeoutMillis) { callback.await() }
                        ?: throw JvmOAuthException("auth/timeout: timed out waiting for the Google OAuth callback")
                parameters["error"]?.let { error ->
                    val code = if (error == "access_denied") "auth/user-cancelled" else "auth/invalid-credential"
                    throw JvmOAuthException("$code: Google OAuth returned $error")
                }
                val code =
                    parameters["code"]
                        ?: throw JvmOAuthException("auth/invalid-credential: Google returned no authorization code")
                withContext(dispatcherProvider.io) { exchangeCode(code, verifier, redirectUri) }
            } finally {
                activeCallback.compareAndSet(callback, null)
                activeServer.compareAndSet(server, null)
                server.stop(0)
            }
        }

    override fun close() {
        synchronized(lifecycleLock) {
            if (closed.compareAndSet(false, true)) {
                activeCallback
                    .getAndSet(null)
                    ?.completeExceptionally(
                        JvmOAuthException("auth/user-cancelled: the authentication provider was closed"),
                    )
                activeServer.getAndSet(null)?.stop(0)
            }
        }
    }

    private fun createLoopbackServer(
        expectedState: String,
        callback: CompletableDeferred<Map<String, String>>,
    ): HttpServer {
        val server = HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0)
        server.createContext(CALLBACK_PATH) { exchange ->
            handleCallback(exchange, expectedState, callback)
        }
        return server
    }

    private fun handleCallback(
        exchange: HttpExchange,
        expectedState: String,
        callback: CompletableDeferred<Map<String, String>>,
    ) {
        val parameters = runCatching { parseUniqueQuery(exchange.requestURI.rawQuery.orEmpty()) }.getOrNull()
        val validMethod = exchange.requestMethod == "GET"
        val validPath = exchange.requestURI.path == CALLBACK_PATH
        val validState = parameters?.get("state")?.constantTimeEquals(expectedState) == true
        val accepted = validMethod && validPath && validState && !callback.isCompleted
        val message =
            if (accepted) {
                "Google authorization received. You can return to the application."
            } else {
                "Invalid or expired Google authorization callback."
            }
        try {
            exchange.respond(if (accepted) HTTP_OK else HTTP_BAD_REQUEST, message)
        } finally {
            if (accepted) callback.complete(checkNotNull(parameters))
        }
    }

    private fun exchangeCode(
        code: String,
        verifier: String,
        redirectUri: URI,
    ): JvmGoogleTokens {
        checkOpen()
        val connection = tokenEndpoint.toURL().openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "POST"
            connection.connectTimeout = HTTP_TIMEOUT_MILLIS
            connection.readTimeout = HTTP_TIMEOUT_MILLIS
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            val fields =
                buildList {
                    add("client_id" to config.clientId)
                    config.clientSecret?.let { add("client_secret" to it) }
                    add("code" to code)
                    add("code_verifier" to verifier)
                    add("grant_type" to "authorization_code")
                    add("redirect_uri" to redirectUri.toString())
                }
            val body = form(fields)
            connection.outputStream.use { it.write(body.toByteArray(StandardCharsets.UTF_8)) }
            val status = connection.responseCode
            val responseBody =
                (if (status in HTTP_OK..HTTP_SUCCESS_LAST) connection.inputStream else connection.errorStream)
                    ?.bufferedReader(StandardCharsets.UTF_8)
                    ?.use { it.readText() }
                    .orEmpty()
            if (status !in HTTP_OK..HTTP_SUCCESS_LAST) {
                val providerError = responseBody.jsonString("error").orEmpty()
                throw JvmOAuthException(
                    "auth/invalid-credential: Google token exchange failed ($status, $providerError)",
                )
            }
            val idToken =
                responseBody.jsonString("id_token")
                    ?: throw JvmOAuthException("auth/invalid-credential: Google returned no ID token")
            JvmGoogleTokens(idToken = idToken, accessToken = responseBody.jsonString("access_token"))
        } finally {
            connection.disconnect()
        }
    }

    private fun checkOpen() {
        check(!closed.get()) { "auth/user-cancelled: the authentication provider is closed" }
    }

    private fun randomUrlSafe(byteCount: Int): String =
        ByteArray(byteCount)
            .also(random::nextBytes)
            .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
}

private class JvmOAuthException(
    message: String,
) : IllegalStateException(message)

private fun HttpExchange.respond(
    status: Int,
    message: String,
) {
    val bytes = message.toByteArray(StandardCharsets.UTF_8)
    responseHeaders.set("Content-Type", "text/plain; charset=utf-8")
    sendResponseHeaders(status, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}

private fun parseUniqueQuery(query: String): Map<String, String>? {
    val pairs =
        query
            .split('&')
            .filter(String::isNotBlank)
            .map { field ->
                val parts = field.split('=', limit = 2)
                parts[0].urlDecode() to parts.getOrElse(1) { "" }.urlDecode()
            }
    return pairs.toMap().takeIf { it.size == pairs.size }
}

private fun form(fields: Iterable<Pair<String, String>>): String =
    fields.joinToString("&") { (name, value) -> "${name.urlEncode()}=${value.urlEncode()}" }

private fun String.urlEncode(): String = URLEncoder.encode(this, StandardCharsets.UTF_8.name())

private fun String.urlDecode(): String = URLDecoder.decode(this, StandardCharsets.UTF_8.name())

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

private fun String.jsonString(name: String): String? =
    Regex("\"${Regex.escape(name)}\"\\s*:\\s*\"([^\"]*)\"")
        .find(this)
        ?.groupValues
        ?.get(1)
