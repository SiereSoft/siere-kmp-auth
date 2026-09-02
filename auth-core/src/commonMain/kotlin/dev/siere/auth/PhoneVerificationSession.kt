package dev.siere.auth

/**
 * An in-progress phone verification, returned by [AuthProvider.startPhoneSignIn] or
 * [AuthProvider.startPhoneLinking] once verification has started. A platform may complete
 * verification automatically; consumers must observe [AuthProvider.authState] as the source of
 * truth and only ask for a code while the expected state transition has not occurred. Otherwise,
 * confirm with the code the user received. A linking session never replaces a different user.
 *
 * A session is single-use. Repeated confirmation returns the terminal result when the platform can
 * cache it; otherwise a failed confirmation may require starting a new session.
 */
public interface PhoneVerificationSession {
    /** The phone number this session is verifying, in E.164 format. */
    public val phoneNumber: String

    /** Exchanges [code] for the signed-in or newly linked user selected when this session began. */
    public suspend fun confirm(code: String): AuthResult<AuthUser>
}
