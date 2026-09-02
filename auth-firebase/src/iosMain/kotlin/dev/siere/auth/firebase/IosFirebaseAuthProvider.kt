@file:OptIn(kotlinx.cinterop.BetaInteropApi::class)
@file:Suppress(
    "CONFLICTING_OVERLOADS",
    "PARAMETER_NAME_CHANGED_ON_OVERRIDE",
    "ktlint:standard:function-naming",
)

package dev.siere.auth.firebase

import dev.gitlive.firebase.auth.AuthCredential
import dev.gitlive.firebase.auth.GoogleAuthProvider
import dev.gitlive.firebase.auth.OAuthProvider
import dev.gitlive.firebase.auth.PhoneAuthProvider
import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthUser
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.PhoneVerificationSession
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import platform.AuthenticationServices.ASAuthorization
import platform.AuthenticationServices.ASAuthorizationAppleIDCredential
import platform.AuthenticationServices.ASAuthorizationAppleIDProvider
import platform.AuthenticationServices.ASAuthorizationController
import platform.AuthenticationServices.ASAuthorizationControllerDelegateProtocol
import platform.AuthenticationServices.ASAuthorizationControllerPresentationContextProvidingProtocol
import platform.AuthenticationServices.ASAuthorizationErrorCanceled
import platform.AuthenticationServices.ASAuthorizationScopeEmail
import platform.AuthenticationServices.ASAuthorizationScopeFullName
import platform.AuthenticationServices.ASPresentationAnchor
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.Foundation.NSError
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecSuccess
import platform.Security.kSecRandomDefault
import platform.UIKit.UIApplication
import platform.darwin.NSObject

/**
 * Presents the platform's Google sign-in UI and reports the resulting tokens.
 *
 * The GoogleSignIn SDK ships via Swift Package Manager, so the presentation half of the
 * Google flow lives in the app's Swift code; the Firebase credential exchange stays in
 * Kotlin. A typical implementation wraps `GIDSignIn.sharedInstance.signIn(withPresenting:)`.
 */
public fun interface GoogleSignInPresenter {
    public fun present(
        onTokens: (idToken: String, accessToken: String) -> Unit,
        onError: (message: String) -> Unit,
    )
}

/** Supplies the attached window used to present Sign in with Apple. */
public fun interface ApplePresentationAnchorProvider {
    public fun presentationAnchor(): ASPresentationAnchor
}

/**
 * Creates the Firebase-backed [dev.siere.auth.AuthProvider] for iOS.
 *
 * `FirebaseApp.configure()` must have run before construction. Pass a [googleSignIn]
 * presenter to enable the Google flows; without one they report a clear failure.
 */
public fun FirebaseAuthProvider(
    googleSignIn: GoogleSignInPresenter? = null,
    dispatcherProvider: dev.siere.auth.DispatcherProvider = dev.siere.auth.DefaultDispatcherProvider(),
    applePresentationAnchorProvider: ApplePresentationAnchorProvider =
        ApplePresentationAnchorProvider {
            UIApplication.sharedApplication.keyWindow
        },
): dev.siere.auth.AuthProvider =
    IosFirebaseAuthProvider(
        googleSignIn,
        dispatcherProvider,
        applePresentationAnchorProvider,
    )

internal class IosFirebaseAuthProvider(
    private val googleSignIn: GoogleSignInPresenter?,
    dispatcherProvider: DispatcherProvider,
    private val applePresentationAnchorProvider: ApplePresentationAnchorProvider,
) : GitLiveFirebaseAuthProvider("iOS", dispatcherProvider) {
    private val mainDispatcher = dispatcherProvider.main

    override suspend fun signInWithApple(): AuthResult<AuthUser> = withAppleCredential(expectedUid = null)

    override suspend fun linkWithApple(): AuthResult<AuthUser> {
        val uid = firebase.currentUser?.uid ?: return AuthResult.Failure(AuthError.NotSignedIn())
        return withAppleCredential(expectedUid = uid)
    }

    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = withGoogleCredential(expectedUid = null)

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> {
        val uid = firebase.currentUser?.uid ?: return AuthResult.Failure(AuthError.NotSignedIn())
        return withGoogleCredential(expectedUid = uid)
    }

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        startPhoneVerification(phoneNumber, linking = false)

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        if (firebase.currentUser == null) {
            return AuthResult.Failure(AuthError.NotSignedIn())
        }
        return startPhoneVerification(phoneNumber, linking = true)
    }

    private suspend fun signInWith(credential: AuthCredential): AuthResult<AuthUser> =
        runCatchingAuth {
            firebase.signInWithCredential(credential).user?.toAuthUser()
                ?: error("Firebase returned no user")
        }

    private suspend fun linkWith(
        credential: AuthCredential,
        expectedUid: String,
    ): AuthResult<AuthUser> =
        runCatchingAuth {
            withExpectedUser(expectedUid, { firebase.currentUser?.uid }) {
                val user = firebase.currentUser ?: throw FirebaseAuthStateChangedException()
                user.linkWithCredential(credential).user?.toAuthUser()
                    ?: error("Firebase returned no user")
            }
        }

    private suspend fun withAppleCredential(expectedUid: String?): AuthResult<AuthUser> {
        val tokens =
            withContext(mainDispatcher) {
                requestAppleTokens(applePresentationAnchorProvider)
            }
        if (tokens is AuthResult.Failure) return tokens
        tokens as AuthResult.Success
        return runCatchingAuth {
            OAuthProvider.credential(
                providerId = "apple.com",
                idToken = tokens.value.idToken,
                rawNonce = tokens.value.rawNonce,
            )
        }.let { credential ->
            when (credential) {
                is AuthResult.Success ->
                    expectedUid?.let { linkWith(credential.value, it) }
                        ?: signInWith(credential.value)
                is AuthResult.Failure -> credential
            }
        }
    }

    private suspend fun withGoogleCredential(expectedUid: String?): AuthResult<AuthUser> {
        val presenter =
            googleSignIn ?: return AuthResult.Failure(
                AuthError.ProviderDisabled("No GoogleSignInPresenter was supplied to FirebaseAuthProvider"),
            )
        val deferred = CompletableDeferred<AuthResult<Pair<String, String>>>()
        try {
            withContext(mainDispatcher) {
                presenter.present(
                    onTokens = { idToken, accessToken ->
                        deferred.complete(AuthResult.Success(idToken to accessToken))
                    },
                    onError = { message ->
                        deferred.complete(AuthResult.Failure(firebaseAuthError(message)))
                    },
                )
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Throwable) {
            return AuthResult.Failure(firebaseAuthError(failure.message))
        }
        return when (val tokens = awaitPlatformCallback(deferred)) {
            is AuthResult.Success ->
                when (
                    val credential =
                        runCatchingAuth {
                            GoogleAuthProvider.credential(tokens.value.first, tokens.value.second)
                        }
                ) {
                    is AuthResult.Success ->
                        expectedUid?.let { linkWith(credential.value, it) }
                            ?: signInWith(credential.value)
                    is AuthResult.Failure -> credential
                }
            is AuthResult.Failure -> tokens
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private suspend fun startPhoneVerification(
        phoneNumber: String,
        linking: Boolean,
    ): AuthResult<PhoneVerificationSession> =
        try {
            val expectedUid =
                if (linking) {
                    firebase.currentUser?.uid
                        ?: return AuthResult.Failure(AuthError.NotSignedIn())
                } else {
                    null
                }
            val provider = PhoneAuthProvider(firebase)
            val verificationId =
                withTimeoutOrNull(PLATFORM_CALLBACK_TIMEOUT_MILLIS) {
                    withContext(mainDispatcher) {
                        requestIosPhoneVerificationId(provider, phoneNumber)
                    }
                } ?: AuthResult.Failure(
                    AuthError.Network("Timed out waiting for the platform authentication callback"),
                )
            when (verificationId) {
                is AuthResult.Success ->
                    AuthResult.Success(
                        IosPhoneSession(phoneNumber, verificationId.value, provider, expectedUid),
                    )
                is AuthResult.Failure -> verificationId
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Throwable) {
            AuthResult.Failure(firebaseAuthError(failure.message))
        }

    private inner class IosPhoneSession(
        override val phoneNumber: String,
        private val verificationId: String,
        private val provider: PhoneAuthProvider,
        private val expectedUid: String?,
    ) : PhoneVerificationSession {
        private val completion = SingleUseAuthOperation<AuthUser>()

        override suspend fun confirm(code: String): AuthResult<AuthUser> =
            completion.complete {
                when (val credential = runCatchingAuth { provider.credential(verificationId, code) }) {
                    is AuthResult.Success ->
                        expectedUid?.let { linkWith(credential.value, it) }
                            ?: signInWith(credential.value)
                    is AuthResult.Failure -> credential
                }
            }
    }
}

private class AppleTokens(
    val idToken: String,
    val rawNonce: String,
)

// ASAuthorizationController holds its delegate weakly; keep a strong reference for the flow
private var activeDelegate: AppleSignInDelegate? = null
private val appleSignInMutex = Mutex()

private suspend fun requestAppleTokens(anchorProvider: ApplePresentationAnchorProvider): AuthResult<AppleTokens> =
    try {
        appleSignInMutex.withLock {
            val anchor =
                anchorProvider.presentationAnchor() ?: return@withLock AuthResult.Failure(
                    AuthError.ProviderDisabled("No attached iOS window is available to present Sign in with Apple"),
                )
            // Firebase requires a nonce: the SHA256 goes to Apple, the raw value to Firebase
            val rawNonce = secureNonce()
            val request =
                ASAuthorizationAppleIDProvider().createRequest().apply {
                    requestedScopes = listOf(ASAuthorizationScopeFullName, ASAuthorizationScopeEmail)
                    nonce = sha256(rawNonce)
                }
            val deferred = CompletableDeferred<AuthResult<AppleTokens>>()
            val delegate = AppleSignInDelegate(rawNonce, anchor, deferred)
            try {
                activeDelegate = delegate
                ASAuthorizationController(authorizationRequests = listOf(request)).apply {
                    this.delegate = delegate
                    presentationContextProvider = delegate
                    performRequests()
                }
                awaitPlatformCallback(deferred)
            } finally {
                if (activeDelegate === delegate) activeDelegate = null
            }
        }
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: Throwable) {
        AuthResult.Failure(firebaseAuthError(failure.message))
    }

@OptIn(ExperimentalForeignApi::class)
private fun secureNonce(length: Int = 32): String {
    val bytes = UByteArray(length)
    val status =
        bytes.usePinned {
            SecRandomCopyBytes(kSecRandomDefault, length.convert(), it.addressOf(0))
        }
    check(status == errSecSuccess) { "Unable to generate a cryptographically secure Apple nonce" }
    return bytes.joinToString("") { APPLE_NONCE_ALPHABET[(it.toInt() and 63)].toString() }
}

private class AppleSignInDelegate(
    private val rawNonce: String,
    private val presentationAnchor: ASPresentationAnchor,
    private val deferred: CompletableDeferred<AuthResult<AppleTokens>>,
) : NSObject(),
    ASAuthorizationControllerDelegateProtocol,
    ASAuthorizationControllerPresentationContextProvidingProtocol {
    override fun authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization: ASAuthorization,
    ) {
        activeDelegate = null
        val credential = didCompleteWithAuthorization.credential as? ASAuthorizationAppleIDCredential
        val idToken =
            credential?.identityToken?.let {
                NSString.create(data = it, encoding = NSUTF8StringEncoding)?.toString()
            }
        deferred.complete(
            if (idToken == null) {
                AuthResult.Failure(AuthError.Unknown("Apple did not return an identity token"))
            } else {
                AuthResult.Success(AppleTokens(idToken, rawNonce))
            },
        )
    }

    override fun authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError: NSError,
    ) {
        activeDelegate = null
        val error =
            if (didCompleteWithError.code == ASAuthorizationErrorCanceled) {
                AuthError.Cancelled(providerCode = "ASAuthorizationError/${didCompleteWithError.code}")
            } else {
                AuthError.Unknown(
                    message = "Apple authorization failed",
                    providerCode = "ASAuthorizationError/${didCompleteWithError.code}",
                )
            }
        deferred.complete(AuthResult.Failure(error))
    }

    override fun presentationAnchorForAuthorizationController(controller: ASAuthorizationController): ASPresentationAnchor =
        presentationAnchor
}

@OptIn(ExperimentalForeignApi::class)
private fun sha256(input: String): String {
    val bytes = input.encodeToByteArray()
    val digest = UByteArray(CC_SHA256_DIGEST_LENGTH)
    bytes.usePinned { pinned ->
        digest.usePinned { digestPinned ->
            CC_SHA256(pinned.addressOf(0), bytes.size.convert(), digestPinned.addressOf(0))
        }
    }
    return digest.joinToString("") { it.toString(16).padStart(2, '0') }
}
