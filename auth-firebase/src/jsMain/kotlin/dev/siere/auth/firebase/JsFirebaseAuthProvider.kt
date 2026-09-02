@file:Suppress("ktlint:standard:function-naming")

package dev.siere.auth.firebase

import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.FirebaseOptions
import dev.gitlive.firebase.auth.externals.GoogleAuthProvider
import dev.gitlive.firebase.auth.externals.OAuthProvider
import dev.gitlive.firebase.auth.externals.PhoneAuthProvider
import dev.gitlive.firebase.auth.externals.getAuth
import dev.gitlive.firebase.auth.externals.signInWithCredential
import dev.gitlive.firebase.auth.externals.signInWithPopup
import dev.gitlive.firebase.initialize
import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthUser
import dev.siere.auth.PhoneVerificationSession
import kotlinx.browser.document
import kotlinx.coroutines.await
import dev.gitlive.firebase.auth.externals.AuthProvider as JsAuthProvider

/**
 * Creates the Firebase-backed [dev.siere.auth.AuthProvider] for the `js` target,
 * initializing the Firebase web app from [options] on first use.
 */
public fun FirebaseAuthProvider(
    options: FirebaseWebOptions,
    dispatcherProvider: dev.siere.auth.DispatcherProvider = dev.siere.auth.DefaultDispatcherProvider(),
): dev.siere.auth.AuthProvider {
    initializeIfNeeded(options)
    return JsFirebaseAuthProvider(options, dispatcherProvider)
}

private var initializedOptions: FirebaseWebOptions? = null

private fun initializeIfNeeded(options: FirebaseWebOptions) {
    initializedOptions?.let { existing ->
        requireCompatibleWebConfiguration(existing, options)
        return
    }
    Firebase.initialize(
        null,
        options =
            FirebaseOptions(
                applicationId = options.applicationId,
                apiKey = options.apiKey,
                authDomain = options.authDomain,
                projectId = options.projectId,
            ),
    )
    initializedOptions = options
}

private const val RECAPTCHA_CONTAINER_ID = "siere-recaptcha-container"

internal class JsFirebaseAuthProvider(
    private val options: FirebaseWebOptions,
    dispatcherProvider: dev.siere.auth.DispatcherProvider,
) : GitLiveFirebaseAuthProvider("JS", dispatcherProvider) {
    private var verifier: RecaptchaVerifier? = null

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = popupSignIn(GoogleAuthProvider())

    override suspend fun signInWithApple(): AuthResult<AuthUser> = popupSignIn(appleProvider())

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = popupLink(GoogleAuthProvider())

    override suspend fun linkWithApple(): AuthResult<AuthUser> = popupLink(appleProvider())

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        startPhoneVerification(phoneNumber, expectedUid = null)

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        val uid = getAuth().currentUser?.uid
        if (uid == null) {
            return AuthResult.Failure(AuthError.NotSignedIn())
        }
        return startPhoneVerification(phoneNumber, expectedUid = uid)
    }

    private suspend fun startPhoneVerification(
        phoneNumber: String,
        expectedUid: String?,
    ): AuthResult<PhoneVerificationSession> =
        runCatchingAuth {
            val auth = getAuth()
            if (options.appVerificationDisabledForTesting) {
                auth.asDynamic().settings.appVerificationDisabledForTesting = true
            }
            // reCAPTCHA tokens are single-use: a fresh verifier per attempt, or Firebase
            // answers auth/invalid-app-credential on every retry.
            verifier?.clear()
            val recaptcha =
                RecaptchaVerifier(
                    auth,
                    recaptchaContainer(),
                    js("({ size: 'invisible' })"),
                ).also { verifier = it }
            val verificationId = PhoneAuthProvider(auth).verifyPhoneNumber(phoneNumber, recaptcha).await()
            JsPhoneSession(phoneNumber, verificationId, expectedUid)
        }

    private suspend fun popupSignIn(provider: JsAuthProvider): AuthResult<AuthUser> =
        runCatchingAuth {
            signInWithPopup(getAuth(), provider).await()
            signedInUser()
        }

    private suspend fun popupLink(provider: JsAuthProvider): AuthResult<AuthUser> {
        val user =
            getAuth().currentUser
                ?: return AuthResult.Failure(AuthError.NotSignedIn())
        val expectedUid = user.uid
        val result =
            runCatchingAuth {
                linkWithPopup(user, provider).await()
                signedInUser()
            }
        return if (result is AuthResult.Success && getAuth().currentUser?.uid != expectedUid) {
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

    private fun signedInUser(): AuthUser = firebase.currentUser?.toAuthUser() ?: error("Firebase returned no user")

    private inner class JsPhoneSession(
        override val phoneNumber: String,
        private val verificationId: String,
        private val expectedUid: String?,
    ) : PhoneVerificationSession {
        private val completion = SingleUseAuthOperation<AuthUser>()

        override suspend fun confirm(code: String): AuthResult<AuthUser> =
            completion.complete {
                if (expectedUid != null && getAuth().currentUser?.uid != expectedUid) {
                    return@complete AuthResult.Failure(AuthError.AuthStateChanged())
                }
                runCatchingAuth {
                    val credential = PhoneAuthProvider.credential(verificationId, code)
                    if (expectedUid != null) {
                        withExpectedUser(expectedUid, { getAuth().currentUser?.uid }) {
                            val user = getAuth().currentUser ?: throw FirebaseAuthStateChangedException()
                            linkWithCredential(user, credential).await()
                        }
                    } else {
                        signInWithCredential(getAuth(), credential).await()
                    }
                    signedInUser()
                }
            }
    }

    override fun closePlatform() {
        verifier?.clear()
        verifier = null
    }
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
