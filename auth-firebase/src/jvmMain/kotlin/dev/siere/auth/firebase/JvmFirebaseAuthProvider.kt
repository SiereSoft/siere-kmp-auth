@file:Suppress("FunctionNaming", "ktlint:standard:function-naming")

package dev.siere.auth.firebase

import dev.gitlive.firebase.auth.GoogleAuthProvider
import dev.gitlive.firebase.auth.OAuthProvider
import dev.gitlive.firebase.auth.PhoneAuthProvider
import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthUser
import dev.siere.auth.DispatcherProvider
import dev.siere.auth.PhoneVerificationSession

private val E164_PHONE_PATTERN = Regex("^\\+[1-9]\\d{7,14}$")

/**
 * Creates the Firebase-backed [dev.siere.auth.AuthProvider] for desktop JVM.
 *
 * Firebase must be initialized via GitLive's `Firebase.initialize` first.
 */
public fun FirebaseAuthProvider(): dev.siere.auth.AuthProvider = FirebaseAuthProvider(dev.siere.auth.DefaultDispatcherProvider())

public fun FirebaseAuthProvider(dispatcherProvider: DispatcherProvider): dev.siere.auth.AuthProvider =
    JvmFirebaseAuthProvider(oauthClient = null, authBroker = null, dispatcherProvider = dispatcherProvider)

/** Creates Firebase with secure system-browser Google sign-in and linking enabled on JVM. */
public fun FirebaseAuthProvider(
    googleAuthConfig: JvmGoogleAuthConfig,
    browserLauncher: JvmBrowserLauncher = SystemJvmBrowserLauncher,
    dispatcherProvider: DispatcherProvider = dev.siere.auth.DefaultDispatcherProvider(),
): dev.siere.auth.AuthProvider =
    JvmFirebaseAuthProvider(
        oauthClient = DefaultJvmGoogleOAuthClient(googleAuthConfig, browserLauncher, dispatcherProvider),
        authBroker = null,
        dispatcherProvider = dispatcherProvider,
    )

/** Creates Firebase with consumer-hosted Apple and phone authorization enabled on JVM. */
public fun FirebaseAuthProvider(
    authBroker: JvmFirebaseAuthBroker,
    dispatcherProvider: DispatcherProvider = dev.siere.auth.DefaultDispatcherProvider(),
): dev.siere.auth.AuthProvider =
    JvmFirebaseAuthProvider(oauthClient = null, authBroker = authBroker, dispatcherProvider = dispatcherProvider)

/** Creates Firebase with Google plus consumer-hosted Apple and phone authorization enabled on JVM. */
public fun FirebaseAuthProvider(
    googleAuthConfig: JvmGoogleAuthConfig,
    authBroker: JvmFirebaseAuthBroker,
    browserLauncher: JvmBrowserLauncher = SystemJvmBrowserLauncher,
    dispatcherProvider: DispatcherProvider = dev.siere.auth.DefaultDispatcherProvider(),
): dev.siere.auth.AuthProvider =
    JvmFirebaseAuthProvider(
        oauthClient = DefaultJvmGoogleOAuthClient(googleAuthConfig, browserLauncher, dispatcherProvider),
        authBroker = authBroker,
        dispatcherProvider = dispatcherProvider,
    )

internal class JvmFirebaseAuthProvider(
    private val oauthClient: JvmGoogleOAuthClient?,
    private val authBroker: JvmFirebaseAuthBroker?,
    dispatcherProvider: DispatcherProvider,
) : GitLiveFirebaseAuthProvider("JVM", dispatcherProvider) {
    override suspend fun signInWithGoogle(): AuthResult<AuthUser> = withGoogleCredential(linking = false)

    override suspend fun linkWithGoogle(): AuthResult<AuthUser> = withGoogleCredential(linking = true)

    override suspend fun signInWithApple(): AuthResult<AuthUser> = withAppleCredential(linking = false)

    override suspend fun linkWithApple(): AuthResult<AuthUser> = withAppleCredential(linking = true)

    override suspend fun startPhoneSignIn(phoneNumber: String): AuthResult<PhoneVerificationSession> =
        startPhoneVerification(phoneNumber, linking = false)

    override suspend fun startPhoneLinking(phoneNumber: String): AuthResult<PhoneVerificationSession> {
        if (firebase.currentUser == null) return AuthResult.Failure(AuthError.NotSignedIn())
        return startPhoneVerification(phoneNumber, linking = true)
    }

    override fun closePlatform() {
        oauthClient?.close()
        authBroker?.close()
    }

    private suspend fun withGoogleCredential(linking: Boolean): AuthResult<AuthUser> {
        val expectedUid = firebase.currentUser?.uid
        return when {
            oauthClient == null ->
                AuthResult.Failure(
                    AuthError.ProviderDisabled("No JVM Google OAuth configuration was supplied"),
                )

            linking && expectedUid == null -> AuthResult.Failure(AuthError.NotSignedIn())
            else ->
                runCatchingAuth {
                    val tokens = oauthClient.authorize()
                    val credential = GoogleAuthProvider.credential(tokens.idToken, tokens.accessToken)
                    val user =
                        if (linking) {
                            withExpectedUser(checkNotNull(expectedUid), { firebase.currentUser?.uid }) {
                                firebase.currentUser
                                    ?.linkWithCredential(credential)
                                    ?.user
                                    .orFail()
                            }
                        } else {
                            firebase.signInWithCredential(credential).user.orFail()
                        }
                    user.toAuthUser()
                }
        }
    }

    private suspend fun withAppleCredential(linking: Boolean): AuthResult<AuthUser> {
        val expectedUid = firebase.currentUser?.uid
        return when {
            authBroker == null ->
                AuthResult.Failure(AuthError.ProviderDisabled("No JVM Firebase authorization broker was supplied"))

            linking && expectedUid == null -> AuthResult.Failure(AuthError.NotSignedIn())
            else ->
                runCatchingAuth {
                    val assertion =
                        authBroker.authorizeApple(if (linking) JvmAuthOperation.LINK else JvmAuthOperation.SIGN_IN)
                    val credential =
                        OAuthProvider.credential(
                            providerId = "apple.com",
                            idToken = assertion.idToken,
                            rawNonce = assertion.rawNonce,
                        )
                    val user =
                        if (linking) {
                            withExpectedUser(checkNotNull(expectedUid), { firebase.currentUser?.uid }) {
                                firebase.currentUser
                                    ?.linkWithCredential(credential)
                                    ?.user
                                    .orFail()
                            }
                        } else {
                            firebase.signInWithCredential(credential).user.orFail()
                        }
                    user.toAuthUser()
                }
        }
    }

    private suspend fun startPhoneVerification(
        phoneNumber: String,
        linking: Boolean,
    ): AuthResult<PhoneVerificationSession> {
        val expectedUid = firebase.currentUser?.uid
        return when {
            !E164_PHONE_PATTERN.matches(phoneNumber) ->
                AuthResult.Failure(AuthError.InvalidPhoneNumber())

            authBroker == null ->
                AuthResult.Failure(
                    AuthError.ProviderDisabled("No JVM Firebase authorization broker was supplied"),
                )

            linking && expectedUid == null -> AuthResult.Failure(AuthError.NotSignedIn())
            else ->
                runCatchingAuth {
                    val operation = if (linking) JvmAuthOperation.LINK else JvmAuthOperation.SIGN_IN
                    val challenge = authBroker.startPhoneVerification(phoneNumber, operation)
                    JvmPhoneVerificationSession(phoneNumber, challenge, linking, expectedUid, authBroker)
                }
        }
    }

    private inner class JvmPhoneVerificationSession(
        override val phoneNumber: String,
        private val challenge: JvmPhoneChallenge,
        private val linking: Boolean,
        private val expectedUid: String?,
        private val broker: JvmFirebaseAuthBroker,
    ) : PhoneVerificationSession {
        private val completion = SingleUseAuthOperation<AuthUser>()

        override suspend fun confirm(code: String): AuthResult<AuthUser> =
            completion.complete {
                runCatchingAuth {
                    val assertion = broker.completePhoneVerification(challenge, code)
                    val credential =
                        PhoneAuthProvider(firebase).credential(assertion.verificationId, assertion.smsCode)
                    val user =
                        if (linking) {
                            withExpectedUser(checkNotNull(expectedUid), { firebase.currentUser?.uid }) {
                                firebase.currentUser
                                    ?.linkWithCredential(credential)
                                    ?.user
                                    .orFail()
                            }
                        } else {
                            firebase.signInWithCredential(credential).user.orFail()
                        }
                    user.toAuthUser()
                }
            }
    }
}
