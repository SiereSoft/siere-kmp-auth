package dev.siere.auth

/**
 * A typed authentication failure. Errors are values: no exception ever crosses the
 * library boundary, every fallible operation returns an [AuthResult].
 *
 * Providers map their raw error codes onto these types and preserve the original
 * code in [providerCode] for logging and debugging.
 */
public sealed class AuthError {
    /**
     * Diagnostic description, not intended for direct display to end users.
     *
     * Provider implementations may retain an identifier supplied by the user. Apply the host
     * application's PII/redaction policy before writing this value to production logs.
     */
    public abstract val message: String

    /** The provider's raw error code (for example Firebase's `auth/popup-blocked`), if any. */
    public abstract val providerCode: String?

    /** The user dismissed or aborted the flow (closed the popup, cancelled the sheet). */
    public data class Cancelled(
        override val message: String = "The sign-in flow was cancelled",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The browser blocked the sign-in popup before it could open. */
    public data class PopupBlocked(
        override val message: String = "The sign-in popup was blocked by the browser",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The request never reached the provider (offline, DNS, timeout). */
    public data class Network(
        override val message: String = "A network error interrupted the request",
        override val providerCode: String? = null,
    ) : AuthError()

    /** Wrong email/password combination, malformed email, or expired custom credential. */
    public data class InvalidCredentials(
        override val message: String = "The supplied credentials are invalid",
        override val providerCode: String? = null,
    ) : AuthError()

    /** No account exists for the supplied identifier. */
    public data class UserNotFound(
        override val message: String = "No account matches the supplied identifier",
        override val providerCode: String? = null,
    ) : AuthError()

    /** Sign-up attempted with an email that already has an account. */
    public data class EmailAlreadyInUse(
        override val message: String = "An account already exists for this email",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The password does not meet the provider's strength policy. */
    public data class WeakPassword(
        override val message: String = "The password does not meet the strength requirements",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The phone number is not in a valid E.164 format. */
    public data class InvalidPhoneNumber(
        override val message: String = "The phone number is not valid",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The SMS verification code is wrong or expired. */
    public data class InvalidVerificationCode(
        override val message: String = "The verification code is wrong or has expired",
        override val providerCode: String? = null,
    ) : AuthError()

    /** Linking attempted with a credential that already belongs to another account. */
    public data class CredentialAlreadyInUse(
        override val message: String = "This credential is already linked to another account",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The sign-in method is disabled or not fully configured in the provider console. */
    public data class ProviderDisabled(
        override val message: String = "This sign-in method is not enabled for the project",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The operation requires a paid plan on the provider (e.g. Firebase phone auth without Blaze). */
    public data class BillingRequired(
        override val message: String = "This operation requires billing to be enabled on the project",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The provider's region policy blocks the destination (e.g. Firebase SMS region policy). */
    public data class RegionBlocked(
        override val message: String = "The provider's region policy blocks this destination",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The operation needs a signed-in user and none is present. */
    public data class NotSignedIn(
        override val message: String = "No user is signed in",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The signed-in account changed while an interactive linking flow was in progress. */
    public data class AuthStateChanged(
        override val message: String = "The signed-in account changed during authentication",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The operation is sensitive and the session is too old; re-authenticate first. */
    public data class RequiresRecentLogin(
        override val message: String = "This operation requires a recent sign-in",
        override val providerCode: String? = null,
    ) : AuthError()

    /** The requested operation is intentionally unavailable on this provider target. */
    public data class Unsupported(
        public val operation: String,
        public val target: String,
        override val message: String = "$operation is not supported on $target",
        override val providerCode: String? = null,
    ) : AuthError()

    /** Anything the provider reported that has no dedicated type yet. */
    public data class Unknown(
        override val message: String,
        override val providerCode: String? = null,
    ) : AuthError()
}
