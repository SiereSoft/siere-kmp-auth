package dev.siere.auth

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

internal class FakeAuthProvider(
    private val user: AuthUser = AuthUser(uid = "fake-uid", displayName = "Fake User"),
    private var nextError: AuthError? = null,
) : AuthProvider {
    var isClosed: Boolean = false
        private set

    private val state = MutableStateFlow<AuthState>(AuthState.SignedOut)
    override val authState: StateFlow<AuthState> = state

    fun failNextWith(error: AuthError) {
        nextError = error
    }

    fun replaceSignedInUser(replacement: AuthUser) {
        state.value = AuthState.SignedIn(replacement)
    }

    private fun signIn(signedInAs: AuthUser = user): AuthResult<AuthUser> {
        nextError?.let {
            nextError = null
            return AuthResult.Failure(it)
        }
        state.value = AuthState.SignedIn(signedInAs)
        return AuthResult.Success(signedInAs)
    }

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = signIn()

    override suspend fun signInWithApple(): AuthResult<AuthUser> = signIn()

    override suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = signIn(user.copy(email = email, providerIds = listOf("password")))

    override suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = signIn(user.copy(email = email, providerIds = listOf("password")))

    override suspend fun sendPasswordReset(email: String): AuthResult<Unit> {
        nextError?.let {
            nextError = null
            return AuthResult.Failure(it)
        }
        return AuthResult.Success(Unit)
    }

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        nextError?.let {
            nextError = null
            return AuthResult.Failure(it)
        }
        return AuthResult.Success(FakePhoneSession(phoneNumber, expectedUid = null))
    }

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        val uid = (state.value as? AuthState.SignedIn)?.user?.uid
        if (uid == null) {
            return AuthResult.Failure(AuthError.NotSignedIn())
        }
        return AuthResult.Success(FakePhoneSession(phoneNumber, expectedUid = uid))
    }

    override suspend fun signInAnonymously(): AuthResult<AuthUser> = signIn(AuthUser(uid = "guest-uid", isAnonymous = true))

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = signIn()

    override suspend fun linkWithApple(): AuthResult<AuthUser> = signIn()

    override suspend fun currentSession(forceRefresh: Boolean): AuthResult<AuthSession> {
        val signedIn =
            state.value as? AuthState.SignedIn
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        return AuthResult.Success(
            AuthSession(
                user = signedIn.user,
                accessToken = if (forceRefresh) "fake-token-refreshed" else "fake-token",
                expiresAtEpochMillis = 3_600_000,
            ),
        )
    }

    override suspend fun signOut(): AuthResult<Unit> {
        state.value = AuthState.SignedOut
        return AuthResult.Success(Unit)
    }

    override fun close() {
        isClosed = true
    }

    private inner class FakePhoneSession(
        override val phoneNumber: String,
        private val expectedUid: String?,
    ) : PhoneVerificationSession {
        override suspend fun confirm(code: String): AuthResult<AuthUser> =
            if (code == VALID_CODE) {
                val existing = (state.value as? AuthState.SignedIn)?.user
                if (expectedUid != null && existing?.uid != expectedUid) {
                    AuthResult.Failure(AuthError.AuthStateChanged())
                } else {
                    val base = existing ?: user
                    signIn(
                        base.copy(
                            phoneNumber = phoneNumber,
                            isAnonymous = false,
                            providerIds = (base.providerIds.filterNot { it == "anonymous" } + "phone").distinct(),
                        ),
                    )
                }
            } else {
                AuthResult.Failure(AuthError.InvalidVerificationCode())
            }
    }

    companion object {
        const val VALID_CODE = "123456"
    }
}
