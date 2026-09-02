package dev.siere.auth

import kotlinx.coroutines.flow.StateFlow

/**
 * The entry point of Siere KMP Auth.
 *
 * Construct it with any [AuthProvider] implementation and use one API on every target:
 *
 * ```kotlin
 * val auth = SiereAuth(FirebaseAuthProvider(configuration))
 *
 * when (val result = auth.signInWithGoogle()) {
 *     is AuthResult.Success -> welcome(result.value)
 *     is AuthResult.Failure -> show(result.error)
 * }
 * ```
 */
public class SiereAuth(
    private val provider: AuthProvider,
) {
    /** The session state; see [AuthProvider.authState]. */
    public val authState: StateFlow<AuthState> get() = provider.authState

    /** The signed-in user, or `null` while loading or signed out. */
    public val currentUser: AuthUser? get() = (authState.value as? AuthState.SignedIn)?.user

    public suspend fun signInWithGoogle(): AuthResult<AuthUser> = provider.signInWithGoogle()

    public suspend fun signInWithApple(): AuthResult<AuthUser> = provider.signInWithApple()

    public suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = provider.signInWithEmail(email, password)

    public suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = provider.signUpWithEmail(email, password)

    public suspend fun sendPasswordReset(email: String): AuthResult<Unit> = provider.sendPasswordReset(email)

    public suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> = provider.startPhoneSignIn(phoneNumber)

    public suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        provider.startPhoneLinking(phoneNumber)

    public suspend fun signInAnonymously(): AuthResult<AuthUser> = provider.signInAnonymously()

    public suspend fun linkWithGoogle(): AuthResult<AuthUser> = provider.linkWithGoogle()

    public suspend fun linkWithApple(): AuthResult<AuthUser> = provider.linkWithApple()

    public suspend fun currentSession(forceRefresh: Boolean = false): AuthResult<AuthSession> = provider.currentSession(forceRefresh)

    public suspend fun signOut(): AuthResult<Unit> = provider.signOut()

    /** Releases resources owned by the configured provider. */
    public fun close(): Unit = provider.close()
}
