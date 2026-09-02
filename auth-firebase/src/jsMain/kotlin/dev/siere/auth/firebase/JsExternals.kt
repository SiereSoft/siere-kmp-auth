@file:JsModule("firebase/auth")
@file:JsNonModule

package dev.siere.auth.firebase

import dev.gitlive.firebase.auth.externals.ApplicationVerifier
import dev.gitlive.firebase.auth.externals.Auth
import dev.gitlive.firebase.auth.externals.AuthProvider
import dev.gitlive.firebase.auth.externals.AuthResult
import dev.gitlive.firebase.auth.externals.User
import kotlin.js.Promise

// GitLive's externals stop short of these two; we declare them ourselves.

internal external fun linkWithPopup(
    user: User,
    provider: AuthProvider,
): Promise<AuthResult>

internal external fun linkWithCredential(
    user: User,
    credential: dynamic,
): Promise<AuthResult>

internal external class RecaptchaVerifier(
    auth: Auth,
    container: String,
    parameters: dynamic = definedExternally,
) : ApplicationVerifier {
    override val type: String

    override fun verify(): Promise<String>

    fun render(): Promise<Int>

    fun clear()
}
