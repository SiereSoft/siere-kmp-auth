@file:Suppress(
    "MaxLineLength",
    "LongParameterList",
    "SwallowedException",
    "TooGenericExceptionCaught",
    "TooManyFunctions",
)

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import dev.siere.auth.AuthProvider
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.PhoneVerificationSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.time.Clock

internal class MultiplatformOidcAuthProvider(
    private val configuration: OidcConfiguration,
    redirectUri: String,
    authorizationHandler: OidcAuthorizationHandler,
    private val sessionStore: OidcSessionStore,
    private val dispatcherProvider: DispatcherProvider,
    private val nowEpochMillis: () -> Long = { Clock.System.now().toEpochMilliseconds() },
    private val http: MultiplatformOidcHttpClient = MultiplatformOidcHttpClient(),
) : AuthProvider {
    private val scope = CoroutineScope(SupervisorJob() + dispatcherProvider.default)
    private val operations = Mutex()
    private val restored = CompletableDeferred<Unit>()
    private val authorizationFlow =
        MultiplatformOidcAuthorizationFlow(configuration, redirectUri, authorizationHandler)
    private val mutableAuthState = MutableStateFlow<AuthState>(AuthState.Loading)
    private var tokens: MultiplatformOidcTokenSet? = null
    private var activeJob: Job? = null
    private var closed = false

    override val authState: StateFlow<AuthState> = mutableAuthState

    init {
        scope.launch { restore() }
    }

    override suspend fun signInWithOpenId(): AuthResult<AuthUser> =
        operation {
            val metadata = io { http.discover(configuration) }
            val grant = authorizationFlow.authorize(metadata)
            ensureOpen()
            val received =
                io {
                    MultiplatformOidcTokenClient(
                        configuration = configuration,
                        metadata = metadata,
                        verifier = idTokenVerifier(metadata),
                        http = http,
                        nowEpochMillis = nowEpochMillis,
                    ).exchange(grant)
                }
            accept(received)
            received.toMultiplatformUser(configuration.providerId)
        }

    override suspend fun currentSession(forceRefresh: Boolean): AuthResult<AuthSession> =
        operation {
            val current = tokens ?: throw MultiplatformOidcFailure(AuthError.NotSignedIn())
            val expiredSoon =
                current.accessTokenExpiresAtEpochMillis
                    ?.let { it <= nowEpochMillis() + REFRESH_WINDOW_MILLIS } == true
            val usable =
                if (forceRefresh || expiredSoon) {
                    val metadata = io { http.discover(configuration) }
                    val refreshed =
                        try {
                            io {
                                MultiplatformOidcTokenClient(
                                    configuration = configuration,
                                    metadata = metadata,
                                    verifier = idTokenVerifier(metadata),
                                    http = http,
                                    nowEpochMillis = nowEpochMillis,
                                ).refresh(current)
                            }
                        } catch (failure: MultiplatformOidcFailure) {
                            if (failure.error is AuthError.InvalidCredentials) clearSession()
                            throw failure
                        }
                    accept(refreshed)
                    refreshed
                } else {
                    current
                }
            usable.toMultiplatformAuthSession(configuration.providerId)
        }

    override suspend fun signOut(): AuthResult<Unit> = operation { clearSession() }

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = unsupportedMultiplatform("Google sign-in")

    override suspend fun signInWithApple(): AuthResult<AuthUser> = unsupportedMultiplatform("Apple sign-in")

    override suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = unsupportedMultiplatform("Email sign-in")

    override suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = unsupportedMultiplatform("Email sign-up")

    override suspend fun sendPasswordReset(email: String): AuthResult<Unit> = unsupportedMultiplatform("Password reset")

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        unsupportedMultiplatform("Phone sign-in")

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        unsupportedMultiplatform("Phone linking")

    override suspend fun signInAnonymously(): AuthResult<AuthUser> = unsupportedMultiplatform("Anonymous sign-in")

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = unsupportedMultiplatform("Google linking")

    override suspend fun linkWithApple(): AuthResult<AuthUser> = unsupportedMultiplatform("Apple linking")

    override fun close() {
        if (closed) return
        closed = true
        activeJob?.cancel(CancellationException("The OIDC provider was closed"))
        activeJob = null
        scope.cancel()
        http.close()
        tokens = null
        restored.complete(Unit)
    }

    private suspend fun restore() {
        try {
            val restoredTokens =
                io {
                    sessionStore.read()?.let { stored ->
                        val decoded = deserializeMultiplatformTokenSet(stored, configuration)
                        val metadata = http.discover(configuration)
                        decoded.copy(
                            idToken = idTokenVerifier(metadata).verify(decoded.idToken.raw, expectedNonce = null),
                        )
                    }
                }
            if (closed) return
            if (restoredTokens != null && restoredTokens.matches(configuration)) {
                tokens = restoredTokens
                mutableAuthState.value =
                    AuthState.SignedIn(restoredTokens.toMultiplatformUser(configuration.providerId))
            } else {
                if (restoredTokens != null) io { sessionStore.clear() }
                mutableAuthState.value = AuthState.SignedOut
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: MultiplatformOidcFailure) {
            if (failure.error is AuthError.InvalidCredentials) {
                runCatching { io { sessionStore.clear() } }
            }
            mutableAuthState.value = AuthState.SignedOut
        } catch (_: Throwable) {
            mutableAuthState.value = AuthState.SignedOut
        } finally {
            restored.complete(Unit)
        }
    }

    private suspend fun <T> operation(block: suspend () -> T): AuthResult<T> {
        restored.await()
        if (closed) return AuthResult.Failure(AuthError.Cancelled("The OIDC provider is closed"))
        return operations.withLock {
            activeJob = currentCoroutineContext()[Job]
            try {
                ensureOpen()
                AuthResult.Success(block())
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: MultiplatformOidcFailure) {
                AuthResult.Failure(failure.error)
            } catch (failure: Throwable) {
                if (failure.looksLikeNetworkFailure()) {
                    AuthResult.Failure(AuthError.Network(failure.message ?: "OIDC network request failed"))
                } else {
                    AuthResult.Failure(AuthError.Unknown(failure.message ?: "OIDC operation failed"))
                }
            } finally {
                activeJob = null
            }
        }
    }

    private suspend fun accept(value: MultiplatformOidcTokenSet) {
        ensureOpen()
        if (!value.matches(configuration)) {
            throw MultiplatformOidcFailure(
                AuthError.InvalidCredentials("OIDC identity does not match the configured provider"),
            )
        }
        io { sessionStore.write(value.serializeMultiplatform(configuration)) }
        ensureOpen()
        tokens = value
        mutableAuthState.value = AuthState.SignedIn(value.toMultiplatformUser(configuration.providerId))
    }

    private suspend fun clearSession() {
        io { sessionStore.clear() }
        tokens = null
        mutableAuthState.value = AuthState.SignedOut
    }

    private fun idTokenVerifier(metadata: MultiplatformOidcMetadata): MultiplatformOidcIdTokenVerifier =
        MultiplatformOidcIdTokenVerifier(
            metadata = metadata,
            clientId = configuration.clientId,
            clockSkewSeconds = configuration.clockSkewSeconds,
            allowInsecureHttpForTesting = configuration.allowInsecureHttpForTesting,
            http = http,
            nowEpochSeconds = { nowEpochMillis() / 1_000 },
        )

    private suspend fun <T> io(block: suspend () -> T): T = withContext(dispatcherProvider.io) { block() }

    private fun ensureOpen() {
        if (closed) throw MultiplatformOidcFailure(AuthError.Cancelled("The OIDC provider is closed"))
    }
}

private fun MultiplatformOidcTokenSet.matches(configuration: OidcConfiguration): Boolean =
    idToken.audiences.contains(configuration.clientId) && idToken.subject.isNotBlank()

private fun MultiplatformOidcTokenSet.toMultiplatformUser(providerId: String): AuthUser =
    AuthUser(
        uid = "${idToken.issuer}|${idToken.subject}",
        displayName = idToken.claimString("name") ?: idToken.claimString("preferred_username"),
        email = idToken.claimString("email"),
        isEmailVerified = idToken.claimBoolean("email_verified"),
        photoUrl = idToken.claimString("picture"),
        phoneNumber = idToken.claimString("phone_number"),
        providerIds = listOf(providerId),
    )

private fun MultiplatformOidcTokenSet.toMultiplatformAuthSession(providerId: String): AuthSession =
    AuthSession(
        user = toMultiplatformUser(providerId),
        accessToken = accessToken,
        refreshToken = refreshToken,
        expiresAtEpochMillis = accessTokenExpiresAtEpochMillis,
    )

private fun Throwable.looksLikeNetworkFailure(): Boolean =
    this::class.simpleName in
        setOf(
            "ConnectTimeoutException",
            "HttpRequestTimeoutException",
            "IOException",
            "SocketTimeoutException",
            "UnresolvedAddressException",
        )

private fun <T> unsupportedMultiplatform(operation: String): AuthResult<T> =
    AuthResult.Failure(AuthError.Unsupported(operation = operation, target = "OpenID Connect"))

private const val REFRESH_WINDOW_MILLIS = 30_000L
