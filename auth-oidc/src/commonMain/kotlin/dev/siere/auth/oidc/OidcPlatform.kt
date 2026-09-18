@file:Suppress("FunctionNaming", "ktlint:standard:function-naming")

package dev.siere.auth.oidc

import dev.siere.auth.AuthProvider
import dev.siere.auth.DefaultDispatcherProvider
import dev.siere.auth.DispatcherProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** A complete authorization request that the host application must open and complete. */
public data class OidcAuthorizationRequest(
    val authorizationUrl: String,
    val redirectUri: String,
) {
    override fun toString(): String = "OidcAuthorizationRequest(authorizationUrl=<redacted>, redirectUri=$redirectUri)"
}

/**
 * Platform integration boundary for the interactive authorization step.
 *
 * Open [OidcAuthorizationRequest.authorizationUrl] in a secure system browser or browser popup,
 * wait for the registered [OidcAuthorizationRequest.redirectUri], and return the complete callback
 * URL. The library validates the callback URL, state, issuer, code, and ID-token nonce.
 */
public fun interface OidcAuthorizationHandler {
    public suspend fun authorize(request: OidcAuthorizationRequest): String
}

/** Persistence boundary for sensitive OIDC session data. */
public interface OidcSessionStore {
    /** Returns previously stored session bytes, or `null`. */
    public suspend fun read(): ByteArray?

    /** Securely replaces the stored session bytes. */
    public suspend fun write(value: ByteArray)

    /** Removes the stored session. */
    public suspend fun clear()
}

/**
 * Process-local session storage available on every target.
 *
 * This store supports refresh for the lifetime of the provider, but not restoration after process
 * restart. Supply a store backed by the platform credential vault when restoration is required.
 */
public class InMemoryOidcSessionStore : OidcSessionStore {
    private val mutex = Mutex()
    private var value: ByteArray? = null

    override suspend fun read(): ByteArray? = mutex.withLock { value?.copyOf() }

    override suspend fun write(value: ByteArray) {
        mutex.withLock { this.value = value.copyOf() }
    }

    override suspend fun clear() {
        mutex.withLock { value = null }
    }
}

/**
 * Creates an OpenID Connect public client on Android, iOS, JVM, JavaScript, and Wasm.
 *
 * The host owns the platform-specific browser/deep-link integration through
 * [authorizationHandler]. [redirectUri] must exactly match the URI registered with the identity
 * provider. Discovery, PKCE, code exchange, refresh, and signed ID-token validation are performed
 * by Siere Auth.
 */
public fun OidcAuthProvider(
    configuration: OidcConfiguration,
    redirectUri: String,
    authorizationHandler: OidcAuthorizationHandler,
    sessionStore: OidcSessionStore = InMemoryOidcSessionStore(),
    dispatcherProvider: DispatcherProvider = DefaultDispatcherProvider(),
): AuthProvider =
    MultiplatformOidcAuthProvider(
        configuration = configuration,
        redirectUri = redirectUri,
        authorizationHandler = authorizationHandler,
        sessionStore = sessionStore,
        dispatcherProvider = dispatcherProvider,
    )
