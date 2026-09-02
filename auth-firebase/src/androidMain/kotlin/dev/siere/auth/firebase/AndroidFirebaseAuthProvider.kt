@file:Suppress("ktlint:standard:function-naming")

package dev.siere.auth.firebase

import android.app.Activity
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import com.google.android.gms.tasks.Task
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.firebase.FirebaseException
import com.google.firebase.auth.FirebaseAuthException
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.OAuthProvider
import com.google.firebase.auth.PhoneAuthCredential
import com.google.firebase.auth.PhoneAuthOptions
import com.google.firebase.auth.PhoneAuthProvider
import dev.gitlive.firebase.auth.android
import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthUser
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.PhoneVerificationSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Supplies the current resumed, non-finishing [Activity] used by Android authentication UI. */
public fun interface AndroidActivityProvider {
    public fun currentActivity(): Activity?
}

/**
 * Creates Firebase with Android Google, Apple, and phone UI enabled.
 *
 * [googleServerClientId] is the Web OAuth client ID from the consuming Firebase project. It may be
 * omitted when Google sign-in is disabled. The library never retains the supplied activity.
 */
public fun FirebaseAuthProvider(
    activityProvider: AndroidActivityProvider,
    googleServerClientId: String? = null,
    dispatcherProvider: DispatcherProvider = dev.siere.auth.DefaultDispatcherProvider(),
): dev.siere.auth.AuthProvider =
    AndroidFirebaseAuthProvider(
        activityProvider = activityProvider,
        googleServerClientId = googleServerClientId,
        dispatcherProvider = dispatcherProvider,
    )

/** Creates Firebase without interactive Android UI. */
public fun FirebaseAuthProvider(): dev.siere.auth.AuthProvider = FirebaseAuthProvider(dev.siere.auth.DefaultDispatcherProvider())

/** Creates Firebase without interactive Android UI, with injected coroutine dispatchers. */
public fun FirebaseAuthProvider(dispatcherProvider: DispatcherProvider): dev.siere.auth.AuthProvider =
    AndroidFirebaseAuthProvider(
        activityProvider = null,
        googleServerClientId = null,
        dispatcherProvider = dispatcherProvider,
    )

internal class AndroidFirebaseAuthProvider(
    private val activityProvider: AndroidActivityProvider?,
    private val googleServerClientId: String?,
    dispatcherProvider: DispatcherProvider,
) : GitLiveFirebaseAuthProvider("Android", dispatcherProvider) {
    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = withGoogleCredential(false)

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = withGoogleCredential(true)

    override suspend fun signInWithApple(): AuthResult<AuthUser> = withAppleProvider(false)

    override suspend fun linkWithApple(): AuthResult<AuthUser> = withAppleProvider(true)

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        startPhoneVerification(phoneNumber, linking = false)

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        if (firebase.android.currentUser == null) {
            return AuthResult.Failure(AuthError.NotSignedIn())
        }
        return startPhoneVerification(phoneNumber, linking = true)
    }

    private suspend fun withGoogleCredential(linking: Boolean): AuthResult<AuthUser> {
        val expectedUid = if (linking) currentLinkUid() ?: return notSignedInFailure() else null
        val activity = currentActivity() ?: return missingActivityFailure()
        val clientId =
            googleServerClientId?.takeIf { it.isNotBlank() } ?: return AuthResult.Failure(
                AuthError.ProviderDisabled("No Google server client ID was supplied to FirebaseAuthProvider"),
            )
        return runAndroidAuth {
            val option =
                GetGoogleIdOption
                    .Builder()
                    .setServerClientId(clientId)
                    .setFilterByAuthorizedAccounts(false)
                    .build()
            val request = GetCredentialRequest.Builder().addCredentialOption(option).build()
            val response = CredentialManager.create(activity).getCredential(activity, request)
            val custom =
                response.credential as? CustomCredential
                    ?: error("Credential Manager returned an unsupported credential")
            require(custom.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                "Credential Manager returned an unsupported credential type"
            }
            val token = GoogleIdTokenCredential.createFrom(custom.data).idToken
            val credential = GoogleAuthProvider.getCredential(token, null)
            if (linking) {
                withExpectedUser(checkNotNull(expectedUid), ::currentLinkUid) {
                    requireLinkUser(expectedUid).linkWithCredential(credential).awaitTask()
                }
            } else {
                firebase.android.signInWithCredential(credential).awaitTask()
            }
            currentUser()
        }
    }

    private suspend fun withAppleProvider(linking: Boolean): AuthResult<AuthUser> {
        val expectedUid = if (linking) currentLinkUid() ?: return notSignedInFailure() else null
        val activity = currentActivity() ?: return missingActivityFailure()
        return runAndroidAuth {
            val provider =
                OAuthProvider
                    .newBuilder("apple.com", firebase.android)
                    .setScopes(listOf("email", "name"))
                    .build()
            if (linking) {
                withExpectedUser(checkNotNull(expectedUid), ::currentLinkUid) {
                    firebase.android.pendingAuthResult?.awaitTask()
                        ?: requireLinkUser(expectedUid)
                            .startActivityForLinkWithProvider(activity, provider)
                            .awaitTask()
                }
            } else {
                firebase.android.pendingAuthResult?.awaitTask()
                    ?: firebase.android.startActivityForSignInWithProvider(activity, provider).awaitTask()
            }
            currentUser()
        }
    }

    private suspend fun startPhoneVerification(
        phoneNumber: String,
        linking: Boolean,
    ): AuthResult<PhoneVerificationSession> {
        val activity = currentActivity() ?: return missingActivityFailure()
        val expectedUid = if (linking) currentLinkUid() ?: return notSignedInFailure() else null
        val started = CompletableDeferred<AuthResult<PhoneVerificationSession>>()
        val session = AndroidPhoneSession(phoneNumber, linking, expectedUid)
        val callbacks =
            object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                override fun onCodeSent(
                    verificationId: String,
                    forceResendingToken: PhoneAuthProvider.ForceResendingToken,
                ) {
                    session.verificationId = verificationId
                    started.complete(AuthResult.Success(session))
                }

                override fun onVerificationCompleted(credential: PhoneAuthCredential) {
                    session.callbackGate.runIfActive {
                        session.automaticCredential = credential
                        started.complete(AuthResult.Success(session))
                        providerScope.launch { session.completeAutomatically() }
                    }
                }

                override fun onVerificationFailed(error: FirebaseException) {
                    val failure = AuthResult.Failure(androidAuthError(error))
                    if (!started.complete(failure)) providerScope.launch { session.fail(failure) }
                }

                override fun onCodeAutoRetrievalTimeOut(verificationId: String) {
                    session.verificationId = verificationId
                    started.complete(AuthResult.Success(session))
                }
            }
        try {
            PhoneAuthProvider.verifyPhoneNumber(
                PhoneAuthOptions
                    .newBuilder(firebase.android)
                    .setPhoneNumber(phoneNumber)
                    .setTimeout(60L, TimeUnit.SECONDS)
                    .setActivity(activity)
                    .setCallbacks(callbacks)
                    .build(),
            )
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Throwable) {
            return AuthResult.Failure(androidAuthError(failure))
        }
        val result =
            try {
                awaitPlatformCallback(started, timeoutMillis = ANDROID_PHONE_CALLBACK_TIMEOUT_MILLIS)
            } catch (cancellation: CancellationException) {
                session.invalidateCallbacks()
                started.cancel(cancellation)
                throw cancellation
            }
        if (result is AuthResult.Failure) session.invalidateCallbacks()
        return result
    }

    private fun currentActivity(): Activity? =
        activityProvider
            ?.currentActivity()
            ?.takeUnless { it.isFinishing || it.isDestroyed }

    private fun missingActivityFailure(): AuthResult.Failure =
        AuthResult.Failure(
            AuthError.ProviderDisabled("No resumed Android Activity was supplied to FirebaseAuthProvider"),
        )

    private fun notSignedInFailure(): AuthResult.Failure = AuthResult.Failure(AuthError.NotSignedIn())

    private fun currentLinkUid(): String? = firebase.android.currentUser?.uid

    private fun requireLinkUser(expectedUid: String): com.google.firebase.auth.FirebaseUser {
        val user = firebase.android.currentUser ?: throw FirebaseAuthStateChangedException()
        if (user.uid != expectedUid) throw FirebaseAuthStateChangedException()
        return user
    }

    private fun currentUser(): AuthUser =
        firebase.currentUser?.toAuthUser()
            ?: error("Firebase returned no user")

    private inner class AndroidPhoneSession(
        override val phoneNumber: String,
        private val linking: Boolean,
        private val expectedUid: String?,
    ) : PhoneVerificationSession {
        @Volatile var verificationId: String? = null

        @Volatile var automaticCredential: PhoneAuthCredential? = null

        val callbackGate = AndroidPhoneCallbackGate()
        private val completion = SingleUseAuthOperation<AuthUser>()

        fun invalidateCallbacks() {
            callbackGate.invalidate()
        }

        override suspend fun confirm(code: String): AuthResult<AuthUser> =
            completion.complete {
                val credential =
                    automaticCredential ?: PhoneAuthProvider.getCredential(
                        verificationId ?: return@complete AuthResult.Failure(
                            AuthError.InvalidVerificationCode("Firebase has not supplied a verification ID"),
                        ),
                        code,
                    )
                runAndroidAuth {
                    if (linking) {
                        withExpectedUser(checkNotNull(expectedUid), ::currentLinkUid) {
                            requireLinkUser(expectedUid).linkWithCredential(credential).awaitTask()
                        }
                    } else {
                        firebase.android.signInWithCredential(credential).awaitTask()
                    }
                    currentUser()
                }
            }

        suspend fun completeAutomatically() {
            if (callbackGate.isActive()) confirm("")
        }

        suspend fun fail(failure: AuthResult.Failure): Unit = completion.fail(failure)
    }
}

internal class AndroidPhoneCallbackGate {
    private val active = AtomicBoolean(true)

    fun invalidate() {
        active.set(false)
    }

    fun isActive(): Boolean = active.get()

    fun runIfActive(block: () -> Unit): Boolean {
        if (!active.get()) return false
        block()
        return true
    }
}

private suspend fun <T> Task<T>.awaitTask(): T =
    suspendCancellableCoroutine { continuation ->
        addOnCompleteListener { task ->
            when {
                task.isCanceled -> continuation.cancel(CancellationException("Firebase task was cancelled"))
                task.isSuccessful -> continuation.resume(task.result)
                else ->
                    continuation.resumeWithException(
                        task.exception ?: IllegalStateException("Firebase task failed"),
                    )
            }
        }
    }

private suspend inline fun <T> runAndroidAuth(crossinline block: suspend () -> T): AuthResult<T> =
    try {
        AuthResult.Success(block())
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (_: GetCredentialCancellationException) {
        AuthResult.Failure(AuthError.Cancelled(providerCode = "androidx.credentials/cancelled"))
    } catch (_: FirebaseAuthStateChangedException) {
        AuthResult.Failure(AuthError.AuthStateChanged())
    } catch (failure: Throwable) {
        AuthResult.Failure(androidAuthError(failure))
    }

private fun androidAuthError(failure: Throwable): AuthError {
    val code =
        (failure as? FirebaseAuthException)
            ?.errorCode
            ?.removePrefix("ERROR_")
            ?.lowercase()
            ?.replace('_', '-')
            ?.let { "auth/$it" }
    return firebaseAuthError(listOfNotNull(code, failure.message).joinToString(": "))
}
