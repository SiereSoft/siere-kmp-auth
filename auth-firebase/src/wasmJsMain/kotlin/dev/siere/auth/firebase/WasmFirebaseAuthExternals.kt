@file:JsModule("firebase/auth")
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package dev.siere.auth.firebase

import kotlin.js.Promise

internal external interface Auth : JsAny {
    val currentUser: User?
}

internal external interface User : JsAny {
    val uid: String
    val displayName: String?
    val email: String?
    val emailVerified: Boolean
    val photoURL: String?
    val phoneNumber: String?
    val isAnonymous: Boolean
    val providerData: JsArray<UserInfo>
}

internal external interface UserInfo : JsAny {
    val providerId: String
}

internal external interface UserCredential : JsAny {
    val user: User
}

internal external class GoogleAuthProvider : JsAny

internal external class OAuthProvider(
    providerId: String,
) : JsAny {
    fun addScope(scope: String)
}

internal external class RecaptchaVerifier(
    auth: Auth,
    container: String,
    parameters: JsAny,
) : JsAny {
    fun clear()
}

internal external class PhoneAuthProvider(
    auth: Auth,
) : JsAny {
    fun verifyPhoneNumber(
        phoneNumber: String,
        applicationVerifier: RecaptchaVerifier,
    ): Promise<JsString>

    companion object {
        fun credential(
            verificationId: String,
            verificationCode: String,
        ): JsAny
    }
}

internal external fun getAuth(app: FirebaseApp): Auth

internal external fun onAuthStateChanged(
    auth: Auth,
    callback: (User?) -> Unit,
): JsAny

internal external fun signInWithPopup(
    auth: Auth,
    provider: JsAny,
): Promise<UserCredential>

internal external fun signInWithCredential(
    auth: Auth,
    credential: JsAny,
): Promise<UserCredential>

internal external fun signInAnonymously(auth: Auth): Promise<UserCredential>

internal external fun linkWithPopup(
    user: User,
    provider: JsAny,
): Promise<UserCredential>

internal external fun linkWithCredential(
    user: User,
    credential: JsAny,
): Promise<UserCredential>

internal external fun signInWithEmailAndPassword(
    auth: Auth,
    email: String,
    password: String,
): Promise<UserCredential>

internal external fun createUserWithEmailAndPassword(
    auth: Auth,
    email: String,
    password: String,
): Promise<UserCredential>

internal external fun sendPasswordResetEmail(
    auth: Auth,
    email: String,
): Promise<JsAny?>

internal external fun signOut(auth: Auth): Promise<JsAny?>

internal external fun getIdToken(
    user: User,
    forceRefresh: Boolean,
): Promise<JsString>
