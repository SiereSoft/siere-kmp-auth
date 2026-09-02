package dev.siere.auth.supabase

import dev.siere.auth.AuthError
import io.github.jan.supabase.auth.exception.AuthRestException
import io.github.jan.supabase.exceptions.HttpRequestException

/**
 * Maps Supabase auth failures onto the typed [AuthError] hierarchy, keyed by GoTrue's
 * stable `error_code` values; the raw code is preserved in [AuthError.providerCode].
 */
internal fun supabaseAuthError(failure: Throwable): AuthError {
    if (failure is AuthCompletionTimeoutException) {
        return AuthError.Network()
    }
    if (failure is HttpRequestException) {
        return AuthError.Network()
    }
    if (failure !is AuthRestException) {
        return AuthError.Unknown("Supabase authentication failed")
    }
    val code = failure.errorCode?.value ?: failure.error
    return supabaseAuthError(code, failure.errorDescription)
}

/** Pure GoTrue error-code mapping, split out so the public contract is deterministic to test. */
@Suppress("UNUSED_PARAMETER")
internal fun supabaseAuthError(
    code: String?,
    message: String,
): AuthError =
    when (code) {
        "invalid_credentials", "bad_jwt", "validation_failed" ->
            AuthError.InvalidCredentials(providerCode = code)

        "user_not_found" ->
            AuthError.UserNotFound(providerCode = code)

        "email_exists", "user_already_exists" ->
            AuthError.EmailAlreadyInUse(providerCode = code)

        "phone_exists" ->
            AuthError.CredentialAlreadyInUse(providerCode = code)

        "weak_password" ->
            AuthError.WeakPassword(providerCode = code)

        "otp_expired", "otp_disabled" ->
            AuthError.InvalidVerificationCode(providerCode = code)

        "identity_already_exists", "single_identity_not_deletable" ->
            AuthError.CredentialAlreadyInUse(providerCode = code)

        "provider_disabled", "email_provider_disabled", "phone_provider_disabled",
        "anonymous_provider_disabled", "signup_disabled",
        ->
            AuthError.ProviderDisabled(providerCode = code)

        "over_sms_send_rate_limit", "over_email_send_rate_limit", "over_request_rate_limit" ->
            AuthError.Network(providerCode = code)

        "session_expired", "session_not_found", "refresh_token_not_found" ->
            AuthError.NotSignedIn(providerCode = code)

        "reauthentication_needed", "insufficient_aal" ->
            AuthError.RequiresRecentLogin(providerCode = code)

        else -> AuthError.Unknown("Supabase authentication failed", code)
    }
