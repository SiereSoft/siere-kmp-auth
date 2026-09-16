@file:Suppress("MagicNumber")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.internal.JvmLoopbackCallback
import dev.siere.auth.internal.newJvmPkceRequest
import dev.siere.auth.internal.newJvmSecureRandomValue
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.awt.Desktop
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Opens the system browser for a JVM OpenID Connect authorization request. */
public fun interface JvmOidcBrowserLauncher {
    /** Returns true only when [uri] was handed to a browser. */
    public fun open(uri: URI): Boolean
}

/** Default JVM launcher backed by [Desktop.browse]. */
public object SystemJvmOidcBrowserLauncher : JvmOidcBrowserLauncher {
    override fun open(uri: URI): Boolean =
        runCatching {
            check(Desktop.isDesktopSupported())
            val desktop = Desktop.getDesktop()
            check(desktop.isSupported(Desktop.Action.BROWSE))
            desktop.browse(uri)
        }.isSuccess
}

internal data class OidcAuthorizationGrant(
    val code: String,
    val verifier: String,
    val nonce: String,
    val redirectUri: URI,
)

internal class JvmOidcBrowserFlow(
    private val configuration: OidcConfiguration,
    private val browserLauncher: JvmOidcBrowserLauncher,
    private val dispatcherProvider: DispatcherProvider,
) : AutoCloseable {
    private val operationMutex = Mutex()
    private val lifecycleLock = Any()
    private val closed = AtomicBoolean(false)
    private val activeCallback = AtomicReference<JvmLoopbackCallback?>()

    suspend fun authorize(metadata: OidcMetadata): OidcAuthorizationGrant =
        operationMutex.withLock {
            checkOpen()
            val pkce = newJvmPkceRequest()
            val nonce = newJvmSecureRandomValue(32)
            val callback =
                JvmLoopbackCallback(
                    expectedState = pkce.state,
                    successMessage = "Authorization received. You can return to the application.",
                    failureMessage = "Invalid or expired authorization callback.",
                )
            val redirectUri = callback.redirectUri
            try {
                synchronized(lifecycleLock) {
                    checkOpen()
                    activeCallback.set(callback)
                    callback.start()
                }
                val standard =
                    listOf(
                        "client_id" to configuration.clientId,
                        "redirect_uri" to redirectUri.toString(),
                        "response_type" to "code",
                        "scope" to (configuration.scopes + "openid").joinToString(" "),
                        "code_challenge" to pkce.challenge,
                        "code_challenge_method" to "S256",
                        "state" to pkce.state,
                        "nonce" to nonce,
                    )
                val authorizationUri =
                    metadata.authorizationEndpoint.withQuery(
                        standard + configuration.additionalAuthorizationParameters.toList(),
                    )
                val opened = withContext(dispatcherProvider.io) { browserLauncher.open(authorizationUri) }
                if (!opened) throw OidcFailure(AuthError.PopupBlocked("The system browser could not be opened"))
                val parameters =
                    callback.await(configuration.callbackTimeoutMillis)
                        ?: throw OidcFailure(AuthError.Network("Timed out waiting for the OIDC callback", "timeout"))
                parameters["error"]?.let { code ->
                    throw OidcFailure(oauthError(code, parameters["error_description"] ?: "OIDC authorization failed"))
                }
                parameters["iss"]?.let { issuer ->
                    if (issuer != metadata.issuer) {
                        throw OidcFailure(AuthError.InvalidCredentials("OIDC callback issuer is invalid"))
                    }
                }
                val code =
                    parameters["code"]
                        ?: throw OidcFailure(
                            AuthError.InvalidCredentials("OIDC callback omitted the authorization code"),
                        )
                OidcAuthorizationGrant(code, pkce.verifier, nonce, redirectUri)
            } finally {
                activeCallback.compareAndSet(callback, null)
                callback.close()
            }
        }

    override fun close() {
        synchronized(lifecycleLock) {
            if (closed.compareAndSet(false, true)) {
                activeCallback.getAndSet(null)?.cancel(OidcFailure(AuthError.Cancelled("The OIDC provider was closed")))
            }
        }
    }

    private fun checkOpen() {
        if (closed.get()) throw OidcFailure(AuthError.Cancelled("The OIDC provider is closed"))
    }
}

private fun URI.withQuery(fields: List<Pair<String, String>>): URI {
    val separator = if (rawQuery.isNullOrEmpty()) "?" else "&"
    return URI("$this$separator${fields.formEncode()}")
}
