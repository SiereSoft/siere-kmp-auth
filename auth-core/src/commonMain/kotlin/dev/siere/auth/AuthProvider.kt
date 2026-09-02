package dev.siere.auth

import kotlinx.coroutines.flow.StateFlow

/**
 * The provider SPI: implement this to plug an authentication backend into [SiereAuth].
 *
 * Implementations own every platform detail (popups, native sheets, reCAPTCHA, redirects)
 * and normalize outcomes into [AuthResult] / [AuthError] values. No method may throw.
 *
 * Redirect-based providers: on platforms where an OAuth flow navigates the page away
 * instead of opening a popup, the suspending call may never resume in the current page
 * lifecycle. Implementations must then restore the session on the next start and emit
 * the result through [authState], which consumers should treat as the source of truth.
 */
public interface AuthProvider {
    /**
     * The current session state. Starts as [AuthState.Loading] until the provider has
     * restored (or ruled out) a previous session, then tracks every sign-in and sign-out.
     */
    public val authState: StateFlow<AuthState>

    /** Signs in with the platform's Google flow (popup, sheet, or redirect). */
    public suspend fun signInWithGoogle(): AuthResult<AuthUser>

    /** Signs in with the platform's Apple flow (popup, sheet, or redirect). */
    public suspend fun signInWithApple(): AuthResult<AuthUser>

    /** Signs in an existing email/password account. */
    public suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser>

    /** Creates an email/password account and signs it in. */
    public suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser>

    /** Sends a password-reset message to [email]. */
    public suspend fun sendPasswordReset(email: String): AuthResult<Unit>

    /**
     * Starts phone sign-in for [phoneNumber] (E.164). On success verification has started; the
     * platform may complete automatically or the returned session accepts the received code.
     */
    public suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession>

    /** Starts phone verification that links the verified number to the current user. */
    public suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession>

    /** Signs in as an anonymous guest that can later be upgraded via the link methods. */
    public suspend fun signInAnonymously(): AuthResult<AuthUser>

    /** Links the current user (typically a guest) with a Google credential. */
    public suspend fun linkWithGoogle(): AuthResult<AuthUser>

    /** Links the current user (typically a guest) with an Apple credential. */
    public suspend fun linkWithApple(): AuthResult<AuthUser>

    /**
     * Returns a valid [AuthSession] for the signed-in user, refreshing the token first when
     * it is expired or [forceRefresh] is set. Fails with [AuthError.NotSignedIn] when no
     * user is signed in.
     */
    public suspend fun currentSession(forceRefresh: Boolean = false): AuthResult<AuthSession>

    /** Signs the current user out. Succeeds when no user is signed in. */
    public suspend fun signOut(): AuthResult<Unit>

    /**
     * Releases state observers and provider-owned coroutine work. Safe to call more than once.
     * The default is a no-op for providers that own no resources.
     */
    public fun close(): Unit = Unit
}
