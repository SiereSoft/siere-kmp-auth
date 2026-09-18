@file:Suppress(
    "FunctionNaming",
    "MaxLineLength",
    "SwallowedException",
    "TooGenericExceptionCaught",
    "TooManyFunctions",
    "ktlint:standard:function-naming",
)

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import dev.siere.auth.AuthProvider
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.DefaultDispatcherProvider
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.PhoneVerificationSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.nio.file.Path
import java.time.Clock
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Creates a JVM desktop OpenID Connect provider using Authorization Code Flow, PKCE, and an
 * ephemeral loopback callback. This is a public client: client secrets are intentionally absent.
 */
public fun OidcAuthProvider(
    configuration: OidcConfiguration,
    browserLauncher: JvmOidcBrowserLauncher = SystemJvmOidcBrowserLauncher,
    sessionStore: JvmOidcSessionStore = defaultJvmOidcSessionStore(configuration),
    dispatcherProvider: DispatcherProvider = DefaultDispatcherProvider(),
): AuthProvider =
    JvmOidcAuthProvider(
        configuration = configuration,
        browserLauncher = browserLauncher,
        sessionStore = sessionStore,
        dispatcherProvider = dispatcherProvider,
    )

/**
 * Returns the encrypted file store used by default by [OidcAuthProvider].
 *
 * The key and ciphertext are protected from other OS users where file permissions are supported,
 * but this is not a hardware-backed keychain. Supply a custom store when that stronger boundary is
 * required.
 */
public fun defaultJvmOidcSessionStore(configuration: OidcConfiguration): JvmOidcSessionStore {
    val userHome =
        System.getProperty("user.home")?.takeIf(String::isNotBlank)
            ?: error("user.home is unavailable; supply a JvmOidcSessionStore")
    return EncryptedFileJvmOidcSessionStore(Path.of(userHome, ".siere-auth"), configuration.storageName)
}

internal class JvmOidcAuthProvider(
    private val configuration: OidcConfiguration,
    browserLauncher: JvmOidcBrowserLauncher,
    private val sessionStore: JvmOidcSessionStore,
    private val dispatcherProvider: DispatcherProvider,
    private val clock: Clock = Clock.systemUTC(),
) : AuthProvider {
    private val scope = CoroutineScope(SupervisorJob() + dispatcherProvider.default)
    private val operations = Mutex()
    private val closed = AtomicBoolean(false)
    private val restored = CompletableDeferred<Unit>()
    private val browserFlow = JvmOidcBrowserFlow(configuration, browserLauncher, dispatcherProvider)
    private val mutableAuthState = MutableStateFlow<AuthState>(AuthState.Loading)
    private var tokens: OidcTokenSet? = null

    override val authState: StateFlow<AuthState> = mutableAuthState

    init {
        scope.launch { restore() }
    }

    override suspend fun signInWithOpenId(): AuthResult<AuthUser> =
        operation {
            val metadata = io { discover(configuration) }
            val grant = browserFlow.authorize(metadata)
            val verifier = idTokenVerifier(metadata)
            val received = io { OidcTokenClient(configuration, metadata, verifier, clock).exchange(grant) }
            accept(received)
            received.toUser(configuration.providerId)
        }

    override suspend fun currentSession(forceRefresh: Boolean): AuthResult<AuthSession> =
        operation {
            val current = tokens ?: throw OidcFailure(AuthError.NotSignedIn())
            val expiredSoon =
                current.accessTokenExpiresAtEpochMillis
                    ?.let { it <= clock.millis() + REFRESH_WINDOW_MILLIS } == true
            val usable =
                if (forceRefresh || expiredSoon) {
                    val metadata = io { discover(configuration) }
                    val refreshed =
                        try {
                            io {
                                OidcTokenClient(configuration, metadata, idTokenVerifier(metadata), clock)
                                    .refresh(current)
                            }
                        } catch (failure: OidcFailure) {
                            if (failure.error is AuthError.InvalidCredentials) clearSession()
                            throw failure
                        }
                    accept(refreshed)
                    refreshed
                } else {
                    current
                }
            usable.toAuthSession(configuration.providerId)
        }

    override suspend fun signOut(): AuthResult<Unit> =
        operation {
            clearSession()
        }

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = unsupported("Google sign-in")

    override suspend fun signInWithApple(): AuthResult<AuthUser> = unsupported("Apple sign-in")

    override suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = unsupported("Email sign-in")

    override suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = unsupported("Email sign-up")

    override suspend fun sendPasswordReset(email: String): AuthResult<Unit> = unsupported("Password reset")

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> = unsupported("Phone sign-in")

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> = unsupported("Phone linking")

    override suspend fun signInAnonymously(): AuthResult<AuthUser> = unsupported("Anonymous sign-in")

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = unsupported("Google linking")

    override suspend fun linkWithApple(): AuthResult<AuthUser> = unsupported("Apple linking")

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        browserFlow.close()
        scope.cancel()
        tokens = null
        restored.complete(Unit)
    }

    private suspend fun restore() {
        try {
            val restoredTokens = io { sessionStore.read()?.let { deserializeTokenSet(it, configuration) } }
            if (closed.get()) return
            if (restoredTokens != null && restoredTokens.matches(configuration)) {
                tokens = restoredTokens
                mutableAuthState.value = AuthState.SignedIn(restoredTokens.toUser(configuration.providerId))
            } else {
                if (restoredTokens != null) io { sessionStore.clear() }
                mutableAuthState.value = AuthState.SignedOut
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            runCatching { io { sessionStore.clear() } }
            mutableAuthState.value = AuthState.SignedOut
        } finally {
            restored.complete(Unit)
        }
    }

    private suspend fun <T> operation(block: suspend () -> T): AuthResult<T> {
        restored.await()
        if (closed.get()) return AuthResult.Failure(AuthError.Cancelled("The OIDC provider is closed"))
        return operations.withLock {
            try {
                AuthResult.Success(block())
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: OidcFailure) {
                AuthResult.Failure(failure.error)
            } catch (failure: SocketTimeoutException) {
                AuthResult.Failure(AuthError.Network("The OIDC request timed out", "timeout"))
            } catch (failure: ConnectException) {
                AuthResult.Failure(AuthError.Network("Could not connect to the OIDC provider", "connection"))
            } catch (failure: IOException) {
                AuthResult.Failure(AuthError.Network(failure.message ?: "OIDC network request failed"))
            } catch (failure: Throwable) {
                AuthResult.Failure(AuthError.Unknown(failure.message ?: "OIDC operation failed"))
            }
        }
    }

    private suspend fun accept(value: OidcTokenSet) {
        ensureOpen()
        if (!value.matches(configuration)) {
            throw OidcFailure(AuthError.InvalidCredentials("OIDC identity does not match the configured provider"))
        }
        io { sessionStore.write(value.serialize(configuration)) }
        ensureOpen()
        tokens = value
        mutableAuthState.value = AuthState.SignedIn(value.toUser(configuration.providerId))
    }

    private suspend fun clearSession() {
        io { sessionStore.clear() }
        tokens = null
        mutableAuthState.value = AuthState.SignedOut
    }

    private fun idTokenVerifier(metadata: OidcMetadata): OidcIdTokenVerifier =
        OidcIdTokenVerifier(
            metadata = metadata,
            clientId = configuration.clientId,
            clockSkewSeconds = configuration.clockSkewSeconds,
            allowInsecureHttpForTesting = configuration.allowInsecureHttpForTesting,
            clock = clock,
        )

    private suspend fun <T> io(block: suspend () -> T): T = withContext(dispatcherProvider.io) { block() }

    private fun ensureOpen() {
        if (closed.get()) throw OidcFailure(AuthError.Cancelled("The OIDC provider is closed"))
    }
}

private fun OidcTokenSet.matches(configuration: OidcConfiguration): Boolean =
    idToken.audiences.contains(configuration.clientId) && idToken.subject.isNotBlank()

private fun OidcTokenSet.toUser(providerId: String): AuthUser =
    AuthUser(
        uid = "${idToken.issuer}|${idToken.subject}",
        displayName = idToken.claimString("name") ?: idToken.claimString("preferred_username"),
        email = idToken.claimString("email"),
        isEmailVerified = idToken.claimBoolean("email_verified"),
        photoUrl = idToken.claimString("picture"),
        phoneNumber = idToken.claimString("phone_number"),
        providerIds = listOf(providerId),
    )

private fun OidcTokenSet.toAuthSession(providerId: String): AuthSession =
    AuthSession(
        user = toUser(providerId),
        accessToken = accessToken,
        refreshToken = refreshToken,
        expiresAtEpochMillis = accessTokenExpiresAtEpochMillis,
    )

private fun <T> unsupported(operation: String): AuthResult<T> =
    AuthResult.Failure(AuthError.Unsupported(operation = operation, target = "OpenID Connect"))

private const val REFRESH_WINDOW_MILLIS = 30_000L
