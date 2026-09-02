@file:Suppress("ktlint:standard:function-naming")

package dev.siere.auth.supabase

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.DefaultDispatcherProvider
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.PhoneVerificationSession
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.auth.OtpType
import io.github.jan.supabase.auth.auth
import io.github.jan.supabase.auth.providers.Apple
import io.github.jan.supabase.auth.providers.Google
import io.github.jan.supabase.auth.providers.builtin.Email
import io.github.jan.supabase.auth.providers.builtin.OTP
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.auth.user.UserSession
import io.github.jan.supabase.createSupabaseClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Creates the Supabase-backed [dev.siere.auth.AuthProvider] from project credentials.
 *
 * This factory is suitable for browser redirects and non-redirect operations. Mobile OAuth hosts
 * must instead configure and retain a [SupabaseClient], forward deep links to that client, and use
 * [SupabaseAuthProvider] with the configured client.
 */
public fun SupabaseAuthProvider(
    supabaseUrl: String,
    supabaseKey: String,
): dev.siere.auth.AuthProvider = SupabaseAuthProvider(supabaseUrl, supabaseKey, DefaultDispatcherProvider())

public fun SupabaseAuthProvider(
    supabaseUrl: String,
    supabaseKey: String,
    dispatcherProvider: DispatcherProvider,
): dev.siere.auth.AuthProvider =
    SupabaseAuthProviderImpl(
        client =
            createSupabaseClient(supabaseUrl = supabaseUrl, supabaseKey = supabaseKey) {
                install(Auth)
            },
        ownsClient = true,
        dispatcherProvider = dispatcherProvider,
    )

/**
 * Creates the Supabase-backed [dev.siere.auth.AuthProvider] on an existing configured [client].
 * The caller retains ownership of [client].
 */
public fun SupabaseAuthProvider(client: SupabaseClient): dev.siere.auth.AuthProvider =
    SupabaseAuthProvider(client, DefaultDispatcherProvider())

public fun SupabaseAuthProvider(
    client: SupabaseClient,
    dispatcherProvider: DispatcherProvider,
): dev.siere.auth.AuthProvider = SupabaseAuthProviderImpl(client, ownsClient = false, dispatcherProvider = dispatcherProvider)

internal class SupabaseAuthProviderImpl(
    private val client: SupabaseClient,
    private val ownsClient: Boolean = false,
    dispatcherProvider: DispatcherProvider = DefaultDispatcherProvider(),
) : dev.siere.auth.AuthProvider {
    private val scope = CoroutineScope(SupervisorJob() + dispatcherProvider.default)
    private val closeScope = CoroutineScope(SupervisorJob() + dispatcherProvider.io)
    private val oauthMutex = Mutex()
    private var closed = false

    override val authState: StateFlow<AuthState> =
        client.auth.sessionStatus
            .map { status ->
                when (status) {
                    is SessionStatus.Initializing -> AuthState.Loading
                    is SessionStatus.Authenticated ->
                        status.session.user
                            ?.toAuthUser()
                            ?.let { AuthState.SignedIn(it) }
                            ?: AuthState.SignedOut
                    else -> AuthState.SignedOut
                }
            }.stateIn(scope, SharingStarted.Eagerly, AuthState.Loading)

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> =
        runCatchingSupabase {
            completeOAuthFlow("google.com") { client.auth.signInWith(Google) }
        }

    override suspend fun signInWithApple(): AuthResult<AuthUser> =
        runCatchingSupabase {
            completeOAuthFlow("apple.com") { client.auth.signInWith(Apple) }
        }

    override suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> =
        runCatchingSupabase {
            client.auth.signInWith(Email) {
                this.email = email
                this.password = password
            }
            currentAuthUser()
        }

    override suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> =
        runCatchingSupabase {
            val created =
                client.auth.signUpWith(Email) {
                    this.email = email
                    this.password = password
                }
            // With email confirmation enabled there is no session yet; surface the created user
            created?.toAuthUser() ?: currentAuthUser()
        }

    override suspend fun sendPasswordReset(email: String): AuthResult<Unit> =
        runCatchingSupabase { client.auth.resetPasswordForEmail(email) }

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        runCatchingSupabase {
            client.auth.signInWith(OTP) {
                phone = phoneNumber
                createUser = true
            }
            SupabasePhoneSession(phoneNumber, OtpType.Phone.SMS)
        }

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        if (client.auth.currentUserOrNull() == null) {
            return AuthResult.Failure(AuthError.NotSignedIn())
        }
        return AuthResult.Failure(
            AuthError.Unsupported(
                operation = "Phone credential linking",
                target = "Supabase",
                message = "Supabase phone linking is disabled until upstream phone-change verification is account-unique",
            ),
        )
    }

    override suspend fun signInAnonymously(): AuthResult<AuthUser> =
        runCatchingSupabase {
            client.auth.signInAnonymously()
            currentAuthUser()
        }

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> =
        linkIdentitySafely("google.com") {
            client.auth.linkIdentity(Google)
        }

    override suspend fun linkWithApple(): AuthResult<AuthUser> =
        linkIdentitySafely("apple.com") {
            client.auth.linkIdentity(Apple)
        }

    override suspend fun currentSession(forceRefresh: Boolean): AuthResult<AuthSession> {
        return runCatchingSupabase {
            val existing =
                client.auth.currentSessionOrNull()
                    ?: return AuthResult.Failure(AuthError.NotSignedIn())
            if (shouldRefreshSession(existing.expiresAt, Clock.System.now(), forceRefresh)) {
                client.auth.refreshCurrentSession()
            }
            val session =
                client.auth.currentSessionOrNull()
                    ?: return AuthResult.Failure(AuthError.NotSignedIn())
            session.toAuthSession()
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        }
    }

    override suspend fun signOut(): AuthResult<Unit> = runCatchingSupabase { client.auth.signOut() }

    override fun close() {
        if (closed) return
        closed = true
        scope.cancel()
        if (ownsClient) {
            closeScope.launch {
                try {
                    client.close()
                } catch (_: Throwable) {
                    // close() has no result channel; cleanup failures must not escape asynchronously.
                } finally {
                    closeScope.cancel()
                }
            }
        } else {
            closeScope.cancel()
        }
    }

    private fun currentAuthUser(): AuthUser =
        client.auth.currentUserOrNull()?.toAuthUser()
            ?: error("Supabase completed authentication without a current user")

    private suspend fun completeOAuthFlow(
        expectedProviderId: String,
        startFlow: suspend () -> Unit,
    ): AuthUser =
        oauthMutex.withLock {
            coroutineScope {
                // Subscribe before opening the browser so a fast redirect callback cannot race the collector.
                val completion =
                    async(start = CoroutineStart.UNDISPATCHED) {
                        awaitNextAuthenticatedUser(client.auth.sessionStatus, expectedProviderId = expectedProviderId)
                    }
                try {
                    startFlow()
                    completion.await()
                } catch (failure: Throwable) {
                    completion.cancel()
                    throw failure
                }
            }
        }

    private suspend fun linkIdentitySafely(
        expectedProviderId: String,
        startFlow: suspend () -> Unit,
    ): AuthResult<AuthUser> {
        val expectedUid =
            client.auth.currentUserOrNull()?.id
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        val result = runCatchingSupabase { completeOAuthFlow(expectedProviderId, startFlow) }
        return if (result is AuthResult.Success && result.value.uid != expectedUid) {
            AuthResult.Failure(AuthError.AuthStateChanged())
        } else {
            result
        }
    }

    private inner class SupabasePhoneSession(
        override val phoneNumber: String,
        private val otpType: OtpType.Phone,
    ) : PhoneVerificationSession {
        override suspend fun confirm(code: String): AuthResult<AuthUser> =
            runCatchingSupabase {
                client.auth.verifyPhoneOtp(type = otpType, phone = phoneNumber, token = code)
                currentAuthUser()
            }
    }
}

internal suspend fun awaitNextAuthenticatedUser(
    statuses: StateFlow<SessionStatus>,
    timeoutMillis: Long = 120_000,
    expectedProviderId: String? = null,
): AuthUser {
    val initialUser =
        (statuses.value as? SessionStatus.Authenticated)
            ?.session
            ?.user
            ?.toAuthUser()
    val authenticated =
        withTimeoutOrNull(timeoutMillis) {
            statuses
                .drop(1)
                .first { status ->
                    val candidate =
                        (status as? SessionStatus.Authenticated)
                            ?.session
                            ?.user
                            ?.toAuthUser()
                    candidate != null &&
                        (status.isNew || candidate != initialUser) &&
                        (expectedProviderId == null || expectedProviderId in candidate.providerIds)
                }
        } ?: throw AuthCompletionTimeoutException()
    return (authenticated as SessionStatus.Authenticated).session.user?.toAuthUser()
        ?: error("Supabase authenticated without a user")
}

internal class AuthCompletionTimeoutException :
    RuntimeException(
        "Authentication did not complete before the timeout",
    )

internal fun UserInfo.toAuthUser(): AuthUser =
    AuthUser(
        uid = id,
        displayName =
            userMetadata?.stringOrNull("full_name")
                ?: userMetadata?.stringOrNull("name"),
        email = email,
        isEmailVerified = emailConfirmedAt != null,
        photoUrl = userMetadata?.stringOrNull("avatar_url"),
        phoneNumber = phone?.takeIf { it.isNotEmpty() },
        isAnonymous = isAnonymous == true,
        providerIds =
            buildList {
                addAll(identities?.map { canonicalProviderId(it.provider) }.orEmpty())
                if (isAnonymous == true) add("anonymous")
            }.distinct(),
    )

// Keep this vocabulary aligned with auth-firebase's module-private canonicalFirebaseProviderId.
// Both adapters have contract tests so the shared public vocabulary cannot drift silently.
internal fun canonicalProviderId(providerId: String): String =
    when (providerId) {
        "google", "google.com" -> "google.com"
        "apple", "apple.com" -> "apple.com"
        "email", "password" -> "password"
        else -> providerId
    }

private fun kotlinx.serialization.json.JsonObject.stringOrNull(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

internal fun UserSession.toAuthSession(): AuthSession? =
    user?.let { sessionUser ->
        AuthSession(
            user = sessionUser.toAuthUser(),
            accessToken = accessToken,
            refreshToken = refreshToken,
            expiresAtEpochMillis = expiresAt.toEpochMilliseconds(),
        )
    }

internal fun shouldRefreshSession(
    expiresAt: Instant,
    now: Instant,
    forceRefresh: Boolean,
): Boolean = forceRefresh || expiresAt <= now

private inline fun <T> runCatchingSupabase(block: () -> T): AuthResult<T> =
    try {
        AuthResult.Success(block())
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: Throwable) {
        AuthResult.Failure(supabaseAuthError(failure))
    }
