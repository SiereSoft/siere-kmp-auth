@file:Suppress("MagicNumber")

package dev.siere.auth.oidc

/**
 * Public-client OpenID Connect configuration.
 *
 * Siere uses Authorization Code Flow with PKCE. Client secrets are deliberately unsupported:
 * applications distributed to user devices cannot keep them confidential.
 */
public data class OidcConfiguration(
    val clientId: String,
    val discoveryUrl: String,
    val scopes: Set<String> = setOf("profile", "email"),
    val providerId: String = "oidc",
    val storageName: String = "siere-auth-oidc-${"$clientId@$discoveryUrl".hashCode().toUInt().toString(16)}",
    val additionalAuthorizationParameters: Map<String, String> = emptyMap(),
    val callbackTimeoutMillis: Long = 120_000,
    val clockSkewSeconds: Long = 30,
    val allowInsecureHttpForTesting: Boolean = false,
) {
    init {
        require(clientId.isNotBlank()) { "clientId must not be blank" }
        require(discoveryUrl.isNotBlank()) { "discoveryUrl must not be blank" }
        require(providerId.isNotBlank()) { "providerId must not be blank" }
        require(storageName.isNotBlank()) { "storageName must not be blank" }
        require(scopes.none(String::isBlank)) { "scopes must not contain blank values" }
        require(callbackTimeoutMillis > 0) { "callbackTimeoutMillis must be positive" }
        require(callbackTimeoutMillis <= MAX_CALLBACK_TIMEOUT_MILLIS) {
            "callbackTimeoutMillis must not exceed 10 minutes"
        }
        require(clockSkewSeconds >= 0) { "clockSkewSeconds must not be negative" }
        require(clockSkewSeconds <= MAX_CLOCK_SKEW_SECONDS) { "clockSkewSeconds must not exceed 5 minutes" }
        require(additionalAuthorizationParameters.keys.none(String::isBlank)) {
            "additionalAuthorizationParameters must not contain blank keys"
        }
        require(additionalAuthorizationParameters.keys.none { it.lowercase() in RESERVED_PARAMETERS }) {
            "additionalAuthorizationParameters must not override standard OAuth/OIDC parameters"
        }
    }

    private companion object {
        val RESERVED_PARAMETERS =
            setOf(
                "client_id",
                "redirect_uri",
                "response_type",
                "scope",
                "state",
                "nonce",
                "code_challenge",
                "code_challenge_method",
            )
    }
}

private const val MAX_CALLBACK_TIMEOUT_MILLIS = 10 * 60 * 1_000L
private const val MAX_CLOCK_SKEW_SECONDS = 5 * 60L
