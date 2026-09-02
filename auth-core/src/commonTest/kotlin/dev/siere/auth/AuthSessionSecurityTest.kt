package dev.siere.auth

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse

class AuthSessionSecurityTest {
    @Test
    fun stringRepresentationsNeverExposeCredentials() {
        val session =
            AuthSession(
                user = AuthUser(uid = "user-1"),
                accessToken = "access-marker-secret",
                refreshToken = "refresh-marker-secret",
                expiresAtEpochMillis = 1234,
            )

        val rendered = session.toString()
        val wrapped = AuthResult.Success(session).toString()

        assertFalse("access-marker-secret" in rendered)
        assertFalse("refresh-marker-secret" in rendered)
        assertFalse("access-marker-secret" in wrapped)
        assertFalse("refresh-marker-secret" in wrapped)
        assertContains(rendered, "accessToken=<redacted>")
        assertContains(rendered, "refreshToken=<redacted>")
    }

    @Test
    fun unsupportedErrorIdentifiesOperationAndTarget() {
        val error = AuthError.Unsupported(operation = "Phone sign-in", target = "auth-firebase/iOS")

        assertContains(error.message, "Phone sign-in")
        assertContains(error.message, "auth-firebase/iOS")
    }
}
