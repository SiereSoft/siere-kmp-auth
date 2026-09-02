package dev.siere.auth

/**
 * The authentication session state, exposed as a [kotlinx.coroutines.flow.StateFlow]
 * by [AuthProvider.authState].
 */
public sealed class AuthState {
    /** The provider is still restoring a possible previous session (e.g. right after app start). */
    public data object Loading : AuthState()

    /** A user is signed in. */
    public data class SignedIn(
        val user: AuthUser,
    ) : AuthState()

    /** No user is signed in. */
    public data object SignedOut : AuthState()
}
