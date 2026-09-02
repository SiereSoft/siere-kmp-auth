@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)
@file:Suppress("ktlint:standard:function-naming")

package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.PhoneVerificationSession
import kotlinx.browser.document
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.js.Promise

/**
 * Creates the Firebase-backed [dev.siere.auth.AuthProvider] for the `wasmJs` target,
 * built on hand-rolled bindings over the Firebase JS SDK (which has no official Wasm
 * support), initializing the Firebase web app from [options] on first use.
 */
public fun FirebaseAuthProvider(options: FirebaseWebOptions): dev.siere.auth.AuthProvider = WasmFirebaseAuthProvider(options)

private var sharedAuth: Auth? = null
private var sharedAuthOptions: FirebaseWebOptions? = null

private fun authFor(options: FirebaseWebOptions): Auth {
    sharedAuth?.let { existing ->
        requireCompatibleWebConfiguration(checkNotNull(sharedAuthOptions), options)
        return existing
    }
    return getAuth(
        initializeApp(
            webOptions(
                apiKey = options.apiKey,
                authDomain = options.authDomain,
                projectId = options.projectId,
                appId = options.applicationId,
            ),
        ),
    ).also {
        sharedAuth = it
        sharedAuthOptions = options
    }
}

// Kotlin/Wasm has no dynamic; js() builds the plain JS objects and reads error messages
private fun webOptions(
    apiKey: String,
    authDomain: String,
    projectId: String,
    appId: String,
): JsAny = js("({ apiKey: apiKey, authDomain: authDomain, projectId: projectId, appId: appId })")

private fun invisibleRecaptchaParams(): JsAny = js("({ size: 'invisible' })")

private fun disableAppVerificationForTesting(auth: Auth): Unit = js("{ auth.settings.appVerificationDisabledForTesting = true; }")

private fun messageOf(error: JsAny?): String = js("String((error && error.message) || error)")

private const val RECAPTCHA_CONTAINER_ID = "siere-recaptcha-container"

internal class WasmFirebaseAuthProvider(
    private val options: FirebaseWebOptions,
) : dev.siere.auth.AuthProvider {
    private val auth: Auth = authFor(options)
    private var verifier: RecaptchaVerifier? = null

    private val state = MutableStateFlow<AuthState>(AuthState.Loading)
    override val authState: StateFlow<AuthState> = state

    private var unsubscribe: JsAny? =
        onAuthStateChanged(auth) { user ->
            state.value = user?.let { AuthState.SignedIn(it.toAuthUser()) } ?: AuthState.SignedOut
        }

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = popupSignIn(GoogleAuthProvider())

    override suspend fun signInWithApple(): AuthResult<AuthUser> = popupSignIn(appleProvider())

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = popupLink(GoogleAuthProvider())

    override suspend fun linkWithApple(): AuthResult<AuthUser> = popupLink(appleProvider())

    override suspend fun signInWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> =
        runCatchingWasm {
            signInWithEmailAndPassword(auth, email, password).awaitAuth().user.toAuthUser()
        }

    override suspend fun signUpWithEmail(
        email: String,
        password: String,
    ): AuthResult<AuthUser> =
        runCatchingWasm {
            createUserWithEmailAndPassword(auth, email, password).awaitAuth().user.toAuthUser()
        }

    override suspend fun sendPasswordReset(email: String): AuthResult<Unit> =
        runCatchingWasm {
            sendPasswordResetEmail(auth, email).awaitAuth()
            Unit
        }

    override suspend fun signInAnonymously(): AuthResult<AuthUser> =
        runCatchingWasm { signInAnonymously(auth).awaitAuth().user.toAuthUser() }

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        startPhoneVerification(phoneNumber, expectedUid = null)

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        val uid = auth.currentUser?.uid
        if (uid == null) {
            return AuthResult.Failure(AuthError.NotSignedIn())
        }
        return startPhoneVerification(phoneNumber, expectedUid = uid)
    }

    private suspend fun startPhoneVerification(
        phoneNumber: String,
        expectedUid: String?,
    ): AuthResult<PhoneVerificationSession> =
        runCatchingWasm {
            if (options.appVerificationDisabledForTesting) {
                disableAppVerificationForTesting(auth)
            }
            // reCAPTCHA tokens are single-use: a fresh verifier per attempt, or Firebase
            // answers auth/invalid-app-credential on every retry.
            verifier?.clear()
            val recaptcha =
                RecaptchaVerifier(
                    auth,
                    recaptchaContainer(),
                    invisibleRecaptchaParams(),
                ).also { verifier = it }
            val verificationId =
                PhoneAuthProvider(auth).verifyPhoneNumber(phoneNumber, recaptcha).awaitAuth()
            WasmPhoneSession(
                phoneNumber,
                verificationId.toString(),
                expectedUid,
            )
        }

    override suspend fun currentSession(forceRefresh: Boolean): AuthResult<AuthSession> {
        val user =
            auth.currentUser
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        return runCatchingWasm {
            AuthSession(
                user = user.toAuthUser(),
                accessToken = getIdToken(user, forceRefresh).awaitAuth().toString(),
            )
        }
    }

    override suspend fun signOut(): AuthResult<Unit> =
        runCatchingWasm {
            signOut(auth).awaitAuth()
            Unit
        }

    override fun close() {
        unsubscribe?.let(::invokeJsFunction)
        unsubscribe = null
        verifier?.clear()
        verifier = null
    }

    private suspend fun popupSignIn(provider: JsAny): AuthResult<AuthUser> =
        runCatchingWasm {
            signInWithPopup(auth, provider).awaitAuth().user.toAuthUser()
        }

    private suspend fun popupLink(provider: JsAny): AuthResult<AuthUser> {
        val user =
            auth.currentUser
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        val expectedUid = user.uid
        val result =
            runCatchingWasm {
                linkWithPopup(user, provider).awaitAuth().user.toAuthUser()
            }
        return if (result is AuthResult.Success && auth.currentUser?.uid != expectedUid) {
            AuthResult.Failure(AuthError.AuthStateChanged())
        } else {
            result
        }
    }

    private fun appleProvider(): OAuthProvider =
        OAuthProvider("apple.com").apply {
            addScope("email")
            addScope("name")
        }

    private inner class WasmPhoneSession(
        override val phoneNumber: String,
        private val verificationId: String,
        private val expectedUid: String?,
    ) : PhoneVerificationSession {
        private val completion = SingleUseAuthOperation<AuthUser>()

        override suspend fun confirm(code: String): AuthResult<AuthUser> =
            completion.complete {
                if (expectedUid != null && auth.currentUser?.uid != expectedUid) {
                    return@complete AuthResult.Failure(AuthError.AuthStateChanged())
                }
                runCatchingWasm {
                    val credential = PhoneAuthProvider.credential(verificationId, code)
                    if (expectedUid != null) {
                        withExpectedUser(expectedUid, { auth.currentUser?.uid }) {
                            val user = auth.currentUser ?: throw FirebaseAuthStateChangedException()
                            linkWithCredential(user, credential).awaitAuth().user.toAuthUser()
                        }
                    } else {
                        signInWithCredential(auth, credential).awaitAuth().user.toAuthUser()
                    }
                }
            }
    }
}

private fun User.toAuthUser(): AuthUser {
    val providers =
        buildList {
            for (index in 0 until providerData.length) {
                providerData[index]?.let { add(it.providerId) }
            }
        }
    return firebaseAuthUser(
        uid = uid,
        displayName = displayName,
        email = email,
        isEmailVerified = emailVerified,
        photoUrl = photoURL,
        phoneNumber = phoneNumber,
        isAnonymous = isAnonymous,
        providerIds = providers,
    )
}

/** Bridges a Firebase promise, preserving the JS error message for [firebaseAuthError]. */
private suspend fun <T : JsAny?> Promise<T>.awaitAuth(): T =
    suspendCancellableCoroutine { cont ->
        then { value ->
            cont.resume(value)
            null
        }.catch { error ->
            cont.resumeWithException(FirebaseWebException(messageOf(error)))
            null
        }
    }

private class FirebaseWebException(
    message: String,
) : Exception(message)

private inline fun <T> runCatchingWasm(block: () -> T): AuthResult<T> =
    try {
        AuthResult.Success(block())
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (_: FirebaseAuthStateChangedException) {
        AuthResult.Failure(AuthError.AuthStateChanged())
    } catch (failure: Throwable) {
        AuthResult.Failure(firebaseAuthError(failure.message))
    }

// The invisible reCAPTCHA needs a real DOM element to attach to
private fun recaptchaContainer(): String {
    if (document.getElementById(RECAPTCHA_CONTAINER_ID) == null) {
        val container = document.createElement("div")
        container.setAttribute("id", RECAPTCHA_CONTAINER_ID)
        document.body?.appendChild(container)
    }
    return RECAPTCHA_CONTAINER_ID
}

private fun invokeJsFunction(callback: JsAny): Unit = js("{ callback(); }")
