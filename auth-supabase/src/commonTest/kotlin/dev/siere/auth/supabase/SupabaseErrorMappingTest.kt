package dev.siere.auth.supabase

import dev.siere.auth.AuthError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs

class SupabaseErrorMappingTest {
    @Test
    fun mapsCredentialAndAccountErrors() {
        assertIs<AuthError.InvalidCredentials>(mapped("invalid_credentials"))
        assertIs<AuthError.UserNotFound>(mapped("user_not_found"))
        assertIs<AuthError.EmailAlreadyInUse>(mapped("email_exists"))
        assertIs<AuthError.CredentialAlreadyInUse>(mapped("phone_exists"))
        assertIs<AuthError.WeakPassword>(mapped("weak_password"))
        assertIs<AuthError.InvalidVerificationCode>(mapped("otp_expired"))
        assertIs<AuthError.CredentialAlreadyInUse>(mapped("identity_already_exists"))
    }

    @Test
    fun mapsProviderSessionRateLimitAndReauthenticationErrors() {
        assertIs<AuthError.ProviderDisabled>(mapped("provider_disabled"))
        assertIs<AuthError.Network>(mapped("over_request_rate_limit"))
        assertIs<AuthError.NotSignedIn>(mapped("session_expired"))
        assertIs<AuthError.RequiresRecentLogin>(mapped("reauthentication_needed"))
    }

    @Test
    fun preservesCodeAndFallsBackToUnknown() {
        val mapped = mapped("invalid_credentials")
        assertEquals("invalid_credentials", mapped.providerCode)

        val unknown = mapped("future_error")
        assertIs<AuthError.Unknown>(unknown)
        assertEquals("future_error", unknown.providerCode)
    }

    @Test
    fun providerDescriptionsAreNotExposedAsLoggableMessages() {
        val marker = "person@example.test bearer-marker"
        val mapped = supabaseAuthError("invalid_credentials", marker)

        assertFalse(marker in mapped.message)
        assertEquals("invalid_credentials", mapped.providerCode)
    }

    private fun mapped(code: String): AuthError = supabaseAuthError(code, "GoTrue error: $code")
}
