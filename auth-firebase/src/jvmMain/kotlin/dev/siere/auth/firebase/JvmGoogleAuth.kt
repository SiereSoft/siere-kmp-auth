package dev.siere.auth.firebase

import dev.siere.auth.DispatcherProvider
import dev.siere.auth.internal.JvmLoopbackCallback
import dev.siere.auth.internal.newJvmPkceRequest
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.awt.Desktop
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private const val DEFAULT_GOOGLE_CALLBACK_TIMEOUT_MILLIS = 120_000L
private const val HTTP_OK = 200
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
    private val operationMutex = Mutex()
    private val lifecycleLock = Any()
    private val closed = AtomicBoolean(false)
    private val activeCallback = AtomicReference<JvmLoopbackCallback?>()

    override suspend fun authorize(): JvmGoogleTokens =
        operationMutex.withLock {
            checkOpen()
            val pkce = newJvmPkceRequest()
            val callback =
                JvmLoopbackCallback(
                    expectedState = pkce.state,
                    successMessage = "Google authorization received. You can return to the application.",
                    failureMessage = "Invalid or expired Google authorization callback.",
                )
            val redirectUri = callback.redirectUri

            try {
                synchronized(lifecycleLock) {
                    checkOpen()
                    activeCallback.set(callback)
                    callback.start()
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
                                    "code_challenge" to pkce.challenge,
                                    "code_challenge_method" to "S256",
                                    "state" to pkce.state,
                                    "prompt" to "select_account",
                                ),
                            ),
                    )
                val opened = withContext(dispatcherProvider.io) { browserLauncher.open(authorizationUri) }
                if (!opened) throw JvmOAuthException("auth/popup-blocked: the system browser could not be opened")

                val parameters =
                    callback.await(config.callbackTimeoutMillis)
                        ?: throw JvmOAuthException("auth/timeout: timed out waiting for the Google OAuth callback")
                parameters["error"]?.let { error ->
                    val code = if (error == "access_denied") "auth/user-cancelled" else "auth/invalid-credential"
                    throw JvmOAuthException("$code: Google OAuth returned $error")
                }
                val code =
                    parameters["code"]
                        ?: throw JvmOAuthException("auth/invalid-credential: Google returned no authorization code")
                withContext(dispatcherProvider.io) { exchangeCode(code, pkce.verifier, redirectUri) }
            } finally {
                activeCallback.compareAndSet(callback, null)
                callback.close()
            }
        }

    override fun close() {
        synchronized(lifecycleLock) {
            if (closed.compareAndSet(false, true)) {
                activeCallback.getAndSet(null)?.cancel(
                    JvmOAuthException("auth/user-cancelled: the authentication provider was closed"),
                )
            }
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
}

private class JvmOAuthException(
    message: String,
) : IllegalStateException(message)

private fun form(fields: Iterable<Pair<String, String>>): String =
    fields.joinToString("&") { (name, value) -> "${name.urlEncode()}=${value.urlEncode()}" }

private fun String.urlEncode(): String = URLEncoder.encode(this, StandardCharsets.UTF_8.name())

private fun String.jsonString(name: String): String? =
    Regex("\"${Regex.escape(name)}\"\\s*:\\s*\"([^\"]*)\"")
        .find(this)
        ?.groupValues
        ?.get(1)
