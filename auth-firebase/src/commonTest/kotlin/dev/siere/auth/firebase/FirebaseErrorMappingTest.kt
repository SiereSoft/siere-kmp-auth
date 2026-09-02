package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs

class FirebaseErrorMappingTest {
    @Test
    fun mapsKnownCodesToTypedErrors() {
        assertIs<AuthError.PopupBlocked>(firebaseAuthError("Firebase: Error (auth/popup-blocked)."))
        assertIs<AuthError.Cancelled>(firebaseAuthError("Firebase: Error (auth/popup-closed-by-user)."))
        assertIs<AuthError.Network>(firebaseAuthError("Firebase: Error (auth/network-request-failed)."))
        assertIs<AuthError.InvalidCredentials>(firebaseAuthError("Firebase: Error (auth/invalid-credential)."))
        assertIs<AuthError.UserNotFound>(firebaseAuthError("Firebase: Error (auth/user-not-found)."))
        assertIs<AuthError.BillingRequired>(firebaseAuthError("Firebase: Error (auth/billing-not-enabled)."))
        assertIs<AuthError.InvalidPhoneNumber>(firebaseAuthError("Firebase: Error (auth/invalid-phone-number)."))
        assertIs<AuthError.InvalidVerificationCode>(firebaseAuthError("Firebase: Error (auth/invalid-verification-code)."))
        assertIs<AuthError.CredentialAlreadyInUse>(firebaseAuthError("Firebase: Error (auth/credential-already-in-use)."))
        assertIs<AuthError.EmailAlreadyInUse>(firebaseAuthError("Firebase: Error (auth/email-already-in-use)."))
        assertIs<AuthError.WeakPassword>(firebaseAuthError("Firebase: Error (auth/weak-password)."))
        assertIs<AuthError.RequiresRecentLogin>(firebaseAuthError("Firebase: Error (auth/requires-recent-login)."))
    }

    @Test
    fun mapsFirebaseRestCodesWithoutExposingProviderDiagnostics() {
        val linked = firebaseAuthError("FEDERATED_USER_ID_ALREADY_LINKED: accounts API returned an error")
        assertIs<AuthError.CredentialAlreadyInUse>(linked)
        assertEquals("FEDERATED_USER_ID_ALREADY_LINKED", linked.providerCode)
        assertIs<AuthError.InvalidCredentials>(firebaseAuthError("INVALID_IDP_RESPONSE"))
        assertIs<AuthError.EmailAlreadyInUse>(firebaseAuthError("EMAIL_EXISTS"))
        assertFalse("accounts API" in linked.message)
    }

    @Test
    fun splitsOperationNotAllowedByRegionMention() {
        assertIs<AuthError.RegionBlocked>(
            firebaseAuthError(
                "Firebase: SMS unable to be sent until this region enabled by the app developer. (auth/operation-not-allowed).",
            ),
        )
        assertIs<AuthError.ProviderDisabled>(
            firebaseAuthError("Firebase: Error (auth/operation-not-allowed)."),
        )
    }

    @Test
    fun preservesRawCodeAndFallsBackToUnknown() {
        val mapped = firebaseAuthError("Firebase: Error (auth/popup-blocked).")
        assertEquals("auth/popup-blocked", mapped.providerCode)

        val unknown = firebaseAuthError("something entirely else")
        assertIs<AuthError.Unknown>(unknown)
        assertEquals(null, unknown.providerCode)
    }

    @Test
    fun providerDiagnosticsAreNotExposedAsLoggableMessages() {
        val marker = "person@example.test bearer-marker"
        val mapped = firebaseAuthError("$marker (auth/invalid-credential)")

        assertFalse(marker in mapped.message)
        assertEquals("auth/invalid-credential", mapped.providerCode)
    }
}
