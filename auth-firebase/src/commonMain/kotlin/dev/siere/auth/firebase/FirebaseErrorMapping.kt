package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import kotlinx.coroutines.CancellationException

private val CODE_PATTERN = Regex("auth/[a-z-]+")
private val REST_CODE_PATTERN =
    Regex(
        "\\b(?:FEDERATED_USER_ID_ALREADY_LINKED|EMAIL_EXISTS|INVALID_LOGIN_CREDENTIALS|" +
            "INVALID_IDP_RESPONSE|INVALID_PASSWORD|USER_DISABLED|USER_NOT_FOUND|" +
            "OPERATION_NOT_ALLOWED|WEAK_PASSWORD|TOKEN_EXPIRED)\\b",
    )

/** Runs [block], converting any thrown Firebase error into a typed [AuthResult.Failure]. */
internal inline fun <T> runCatchingAuth(block: () -> T): AuthResult<T> =
    try {
        AuthResult.Success(block())
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (_: FirebaseAuthStateChangedException) {
        AuthResult.Failure(AuthError.AuthStateChanged())
    } catch (failure: Throwable) {
        AuthResult.Failure(firebaseAuthError(failure.message))
    }

/**
 * Maps a raw Firebase Auth error message onto the typed [AuthError] hierarchy.
 *
 * Firebase reports errors as `auth/<code>` strings embedded in the message on every
 * platform; the original code is preserved in [AuthError.providerCode].
 */
internal fun firebaseAuthError(rawMessage: String?): AuthError {
    val diagnostic = rawMessage.orEmpty()
    return when (val code = CODE_PATTERN.find(diagnostic)?.value ?: REST_CODE_PATTERN.find(diagnostic)?.value) {
        "auth/popup-blocked" ->
            AuthError.PopupBlocked(providerCode = code)

        "auth/popup-closed-by-user", "auth/cancelled-popup-request", "auth/user-cancelled" ->
            AuthError.Cancelled(providerCode = code)

        "auth/network-request-failed", "auth/timeout" ->
            AuthError.Network(providerCode = code)

        "auth/invalid-credential", "auth/invalid-email", "auth/wrong-password",
        "auth/invalid-app-credential", "auth/invalid-login-credentials", "INVALID_LOGIN_CREDENTIALS",
        "INVALID_IDP_RESPONSE", "INVALID_PASSWORD", "TOKEN_EXPIRED",
        ->
            AuthError.InvalidCredentials(providerCode = code)

        "auth/user-not-found", "auth/user-disabled", "USER_NOT_FOUND", "USER_DISABLED" ->
            AuthError.UserNotFound(providerCode = code)

        "auth/email-already-in-use", "EMAIL_EXISTS" ->
            AuthError.EmailAlreadyInUse(providerCode = code)

        "auth/weak-password", "auth/password-does-not-meet-requirements", "WEAK_PASSWORD" ->
            AuthError.WeakPassword(providerCode = code)

        "auth/invalid-phone-number", "auth/missing-phone-number" ->
            AuthError.InvalidPhoneNumber(providerCode = code)

        "auth/invalid-verification-code", "auth/code-expired", "auth/missing-verification-code" ->
            AuthError.InvalidVerificationCode(providerCode = code)

        "auth/credential-already-in-use", "auth/provider-already-linked",
        "auth/account-exists-with-different-credential", "FEDERATED_USER_ID_ALREADY_LINKED",
        ->
            AuthError.CredentialAlreadyInUse(providerCode = code)

        "auth/operation-not-allowed", "OPERATION_NOT_ALLOWED" ->
            if ("region" in diagnostic.lowercase()) {
                AuthError.RegionBlocked(providerCode = code)
            } else {
                AuthError.ProviderDisabled(providerCode = code)
            }

        "auth/billing-not-enabled" ->
            AuthError.BillingRequired(providerCode = code)

        "auth/requires-recent-login" ->
            AuthError.RequiresRecentLogin(providerCode = code)

        else -> AuthError.Unknown("Firebase authentication failed", code)
    }
}
