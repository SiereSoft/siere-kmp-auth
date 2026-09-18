@file:Suppress("MagicNumber", "ThrowsCount")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.nio.charset.StandardCharsets
import java.time.Clock

internal data class OidcTokenSet(
    val accessToken: String,
    val refreshToken: String?,
    val idToken: VerifiedIdToken,
    val accessTokenExpiresAtEpochMillis: Long?,
) {
    override fun toString(): String =
        "OidcTokenSet(accessToken=<redacted>, refreshToken=" +
            (if (refreshToken == null) "null" else "<redacted>") +
            ", idToken=<redacted>, accessTokenExpiresAtEpochMillis=$accessTokenExpiresAtEpochMillis)"
}

internal class OidcTokenClient(
    private val configuration: OidcConfiguration,
    private val metadata: OidcMetadata,
    private val verifier: OidcIdTokenVerifier,
    private val clock: Clock = Clock.systemUTC(),
) {
    fun exchange(grant: OidcAuthorizationGrant): OidcTokenSet =
        parse(
            postForm(
                metadata.tokenEndpoint,
                listOf(
                    "grant_type" to "authorization_code",
                    "client_id" to configuration.clientId,
                    "code" to grant.code,
                    "redirect_uri" to grant.redirectUri.toString(),
                    "code_verifier" to grant.verifier,
                ),
            ),
            previous = null,
            expectedNonce = grant.nonce,
        )

    fun refresh(previous: OidcTokenSet): OidcTokenSet {
        val refreshToken =
            previous.refreshToken
                ?: throw OidcFailure(AuthError.InvalidCredentials("The OIDC session has no refresh token"))
        return parse(
            postForm(
                metadata.tokenEndpoint,
                listOf(
                    "grant_type" to "refresh_token",
                    "client_id" to configuration.clientId,
                    "refresh_token" to refreshToken,
                ),
            ),
            previous = previous,
            expectedNonce = null,
        )
    }

    private fun parse(
        response: JsonObject,
        previous: OidcTokenSet?,
        expectedNonce: String?,
    ): OidcTokenSet {
        val tokenType = response.requiredString("token_type")
        if (!tokenType.equals("Bearer", ignoreCase = true)) {
            throw OidcFailure(AuthError.InvalidCredentials("OIDC returned an unsupported token type"))
        }
        val idToken =
            response.optionalString("id_token")?.let { verifier.verify(it, expectedNonce) }
                ?: previous?.idToken
                ?: throw OidcFailure(AuthError.InvalidCredentials("OIDC token response omitted id_token"))
        if (previous != null &&
            (idToken.issuer != previous.idToken.issuer || idToken.subject != previous.idToken.subject)
        ) {
            throw OidcFailure(AuthError.InvalidCredentials("OIDC refresh response changed the authenticated identity"))
        }
        val expiresIn = response["expires_in"]?.jsonPrimitive?.longOrNull
        if (expiresIn != null && expiresIn <= 0) {
            throw OidcFailure(AuthError.InvalidCredentials("OIDC returned an invalid access token lifetime"))
        }
        return OidcTokenSet(
            accessToken = response.requiredString("access_token"),
            refreshToken = response.optionalString("refresh_token") ?: previous?.refreshToken,
            idToken = idToken,
            accessTokenExpiresAtEpochMillis = expiresIn?.let { clock.millis() + it * 1_000 },
        )
    }
}

internal fun OidcTokenSet.serialize(configuration: OidcConfiguration): ByteArray =
    buildJsonObject {
        put("client_id", JsonPrimitive(configuration.clientId))
        put("discovery_url", JsonPrimitive(configuration.discoveryUrl))
        put("access_token", JsonPrimitive(accessToken))
        refreshToken?.let { put("refresh_token", JsonPrimitive(it)) }
        put("id_token", JsonPrimitive(idToken.raw))
        accessTokenExpiresAtEpochMillis?.let { put("expires_at", JsonPrimitive(it)) }
    }.toString().toByteArray(StandardCharsets.UTF_8)

internal fun deserializeTokenSet(
    value: ByteArray,
    configuration: OidcConfiguration,
): OidcTokenSet {
    val json =
        runCatching { oidcJson.parseToJsonElement(String(value, StandardCharsets.UTF_8)).jsonObject }
            .getOrElse { throw OidcFailure(AuthError.InvalidCredentials("Stored OIDC session is malformed"), it) }
    if (json.requiredString("client_id") != configuration.clientId ||
        json.requiredString("discovery_url") != configuration.discoveryUrl
    ) {
        throw OidcFailure(AuthError.InvalidCredentials("Stored OIDC session belongs to another configuration"))
    }
    return OidcTokenSet(
        accessToken = json.requiredString("access_token"),
        refreshToken = json.optionalString("refresh_token"),
        idToken = decodeIdTokenWithoutVerification(json.requiredString("id_token")),
        accessTokenExpiresAtEpochMillis = json["expires_at"]?.jsonPrimitive?.longOrNull,
    )
}
