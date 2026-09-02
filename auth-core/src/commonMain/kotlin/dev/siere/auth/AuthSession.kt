package dev.siere.auth

/**
 * The credentials backing a signed-in [user]: what an app sends to its own backend.
 *
 * A session is a point-in-time snapshot. It is intentionally not part of [AuthState]
 * (tokens expire; state would go stale): fetch a fresh one with
 * [AuthProvider.currentSession] whenever the token is about to leave the app.
 *
 * @property user The identity this session belongs to.
 * @property accessToken The bearer token for backend calls: Firebase's ID token,
 * Supabase's access token. A JWT for both.
 * @property refreshToken The token used to mint new sessions, when the provider exposes it;
 * `null` for providers that refresh internally (Firebase).
 * @property expiresAtEpochMillis When [accessToken] expires, in epoch milliseconds,
 * when the provider shares it.
 */
public data class AuthSession(
    val user: AuthUser,
    val accessToken: String,
    val refreshToken: String? = null,
    val expiresAtEpochMillis: Long? = null,
) {
    /** Returns session metadata without ever rendering bearer or refresh credentials. */
    override fun toString(): String =
        "AuthSession(user=$user, accessToken=<redacted>, refreshToken=" +
            (if (refreshToken == null) "null" else "<redacted>") +
            ", expiresAtEpochMillis=$expiresAtEpochMillis)"
}
