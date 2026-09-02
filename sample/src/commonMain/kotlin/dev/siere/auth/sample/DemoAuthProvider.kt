package dev.siere.auth.sample

import dev.siere.auth.AuthError
import dev.siere.auth.AuthProvider
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.PhoneVerificationSession
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** A deterministic, network-free provider used to exercise the sample without credentials. */
internal class DemoAuthProvider : AuthProvider {
    private val state = MutableStateFlow<AuthState>(AuthState.SignedOut)

    override val authState: StateFlow<AuthState> = state

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = signIn(DEMO_USER.copy(providerIds = listOf("google.com")))

    override suspend fun signInWithApple(): AuthResult<AuthUser> = signIn(DEMO_USER.copy(providerIds = listOf("apple.com")))

    override suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> {
        if (email.isBlank() || password.isBlank()) {
            return AuthResult.Failure(
                AuthError.InvalidCredentials("Enter both an email address and a password"),
            )
        }
        if (password == FAILURE_PASSWORD) {
            return AuthResult.Failure(
                AuthError.InvalidCredentials("Demo failure: the password was rejected", "demo/invalid-password"),
            )
        }
        return signIn(
            DEMO_USER.copy(email = email, isEmailVerified = true, providerIds = listOf("password")),
        )
    }

    override suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> = signInWithEmail(email, password)

    override suspend fun sendPasswordReset(email: String): AuthResult<Unit> =
        if (email.isBlank()) {
            AuthResult.Failure(AuthError.InvalidCredentials("Enter an email address"))
        } else {
            AuthResult.Success(Unit)
        }

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        if (!phoneNumber.startsWith("+") || phoneNumber.length < 8) {
            AuthResult.Failure(AuthError.InvalidPhoneNumber())
        } else {
            AuthResult.Success(DemoPhoneSession(phoneNumber, expectedUid = null))
        }

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        val uid = (state.value as? AuthState.SignedIn)?.user?.uid
        if (uid == null) {
            return AuthResult.Failure(AuthError.NotSignedIn())
        }
        return if (!phoneNumber.startsWith("+") || phoneNumber.length < 8) {
            AuthResult.Failure(AuthError.InvalidPhoneNumber())
        } else {
            AuthResult.Success(DemoPhoneSession(phoneNumber, expectedUid = uid))
        }
    }

    override suspend fun signInAnonymously(): AuthResult<AuthUser> =
        signIn(
            AuthUser(
                uid = "demo-guest",
                displayName = "Demo guest",
                isAnonymous = true,
                providerIds = listOf("anonymous"),
            ),
        )

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = link("google.com")

    override suspend fun linkWithApple(): AuthResult<AuthUser> = link("apple.com")

    override suspend fun currentSession(forceRefresh: Boolean): AuthResult<AuthSession> {
        val user =
            (state.value as? AuthState.SignedIn)?.user
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        return AuthResult.Success(
            AuthSession(
                user = user,
                accessToken = if (forceRefresh) "demo-access-token-refreshed" else "demo-access-token",
                expiresAtEpochMillis = 4_102_444_800_000,
            ),
        )
    }

    override suspend fun signOut(): AuthResult<Unit> {
        state.value = AuthState.SignedOut
        return AuthResult.Success(Unit)
    }

    private fun link(providerId: String): AuthResult<AuthUser> {
        val user =
            (state.value as? AuthState.SignedIn)?.user
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        return signIn(
            user.copy(
                isAnonymous = false,
                providerIds = (user.providerIds.filterNot { it == "anonymous" } + providerId).distinct(),
            ),
        )
    }

    private fun signIn(user: AuthUser): AuthResult<AuthUser> {
        state.value = AuthState.SignedIn(user)
        return AuthResult.Success(user)
    }

    private inner class DemoPhoneSession(
        override val phoneNumber: String,
        private val expectedUid: String?,
    ) : PhoneVerificationSession {
        override suspend fun confirm(code: String): AuthResult<AuthUser> {
            if (code != DEMO_PHONE_CODE) {
                return AuthResult.Failure(AuthError.InvalidVerificationCode())
            }
            if (expectedUid == null) {
                return signIn(
                    DEMO_USER.copy(phoneNumber = phoneNumber, providerIds = listOf("phone")),
                )
            }
            val user =
                (state.value as? AuthState.SignedIn)?.user
                    ?: return AuthResult.Failure(AuthError.AuthStateChanged())
            if (user.uid != expectedUid) return AuthResult.Failure(AuthError.AuthStateChanged())
            return signIn(
                user.copy(
                    phoneNumber = phoneNumber,
                    isAnonymous = false,
                    providerIds = (user.providerIds.filterNot { it == "anonymous" } + "phone").distinct(),
                ),
            )
        }
    }

    companion object {
        internal const val DEMO_PHONE_CODE: String = "123456"
        internal const val FAILURE_PASSWORD: String = "fail"

        private val DEMO_USER =
            AuthUser(
                uid = "demo-user",
                displayName = "Demo User",
                email = "demo@example.test",
                isEmailVerified = true,
                photoUrl = "https://example.test/demo-avatar.png",
            )
    }
}

internal fun demoProviderOption(): ProviderOption = ProviderOption("Demo") { DemoAuthProvider() }
