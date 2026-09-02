package dev.siere.auth.firebase

import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.auth.FirebaseAuth
import dev.gitlive.firebase.auth.FirebaseUser
import dev.gitlive.firebase.auth.auth
import dev.siere.auth.AuthError
import dev.siere.auth.AuthProvider
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.PhoneVerificationSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

/**
 * The shared, GitLive-backed part of the Firebase provider: everything Firebase exposes
 * through its multiplatform API (email/password, anonymous, session, state, sign-out).
 *
 * Interactive flows (OAuth popups and sheets, phone verification) are platform UI and are
 * overridden by the per-target subclasses; targets that don't override them report a clear
 * failure instead of throwing.
 */
internal abstract class GitLiveFirebaseAuthProvider(
    private val targetName: String,
    dispatcherProvider: DispatcherProvider,
) : AuthProvider {
    protected val firebase: FirebaseAuth get() = Firebase.auth

    protected val providerScope: CoroutineScope =
        CoroutineScope(SupervisorJob() + dispatcherProvider.default)

    final override val authState: StateFlow<AuthState> =
        Firebase.auth.authStateChanged
            .map { user -> user?.let { AuthState.SignedIn(it.toAuthUser()) } ?: AuthState.SignedOut }
            .stateIn(providerScope, SharingStarted.Eagerly, AuthState.Loading)

    final override suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> =
        runCatchingAuth {
            firebase
                .signInWithEmailAndPassword(email, password)
                .user
                .orFail()
                .toAuthUser()
        }

    final override suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> =
        runCatchingAuth {
            firebase
                .createUserWithEmailAndPassword(email, password)
                .user
                .orFail()
                .toAuthUser()
        }

    final override suspend fun sendPasswordReset(email: String): AuthResult<Unit> =
        runCatchingAuth { firebase.sendPasswordResetEmail(email) }

    final override suspend fun signInAnonymously(): AuthResult<AuthUser> =
        runCatchingAuth {
            firebase
                .signInAnonymously()
                .user
                .orFail()
                .toAuthUser()
        }

    final override suspend fun currentSession(forceRefresh: Boolean): AuthResult<AuthSession> {
        val user =
            firebase.currentUser
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        return runCatchingAuth {
            val token =
                user.getIdToken(forceRefresh)
                    ?: error("Firebase returned no ID token")
            AuthSession(user = user.toAuthUser(), accessToken = token)
        }
    }

    final override suspend fun signOut(): AuthResult<Unit> = runCatchingAuth { firebase.signOut() }

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = unsupported("Google sign-in")

    override suspend fun signInWithApple(): AuthResult<AuthUser> = unsupported("Apple sign-in")

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> = unsupported("Phone sign-in")

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> = unsupported("Phone linking")

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = unsupported("Google linking")

    override suspend fun linkWithApple(): AuthResult<AuthUser> = unsupported("Apple linking")

    protected fun unsupported(what: String): AuthResult.Failure = unsupportedFirebaseOperation(what, targetName)

    final override fun close() {
        providerScope.cancel()
        closePlatform()
    }

    /** Releases target-specific UI/listener resources. Called once the provider scope is cancelled. */
    protected open fun closePlatform(): Unit = Unit
}

internal fun FirebaseUser.toAuthUser(): AuthUser =
    firebaseAuthUser(
        uid = uid,
        displayName = displayName,
        email = email,
        isEmailVerified = isEmailVerified,
        photoUrl = photoURL,
        phoneNumber = phoneNumber,
        isAnonymous = isAnonymous,
        providerIds = providerData.map { it.providerId },
    )

internal fun FirebaseUser?.orFail(): FirebaseUser = this ?: error("Firebase returned no user")
