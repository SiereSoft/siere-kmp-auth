@file:Suppress("MagicNumber", "MaxLineLength", "ThrowsCount")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlin.time.Clock

internal data class MultiplatformOidcTokenSet(
    val accessToken: String,
    val refreshToken: String?,
    val idToken: MultiplatformVerifiedIdToken,
    val accessTokenExpiresAtEpochMillis: Long?,
) {
    override fun toString(): String =
        "MultiplatformOidcTokenSet(accessToken=<redacted>, refreshToken=" +
            (if (refreshToken == null) "null" else "<redacted>") +
            ", idToken=<redacted>, accessTokenExpiresAtEpochMillis=$accessTokenExpiresAtEpochMillis)"
}

internal class MultiplatformOidcTokenClient(
    private val configuration: OidcConfiguration,
    private val metadata: MultiplatformOidcMetadata,
    private val verifier: MultiplatformOidcIdTokenVerifier,
    private val http: MultiplatformOidcHttpClient,
    private val nowEpochMillis: () -> Long = { Clock.System.now().toEpochMilliseconds() },
) {
    suspend fun exchange(grant: MultiplatformOidcAuthorizationGrant): MultiplatformOidcTokenSet =
        parse(
            http.postForm(
                metadata.tokenEndpoint,
                listOf(
                    "grant_type" to "authorization_code",
                    "client_id" to configuration.clientId,
                    "code" to grant.code,
                    "redirect_uri" to grant.redirectUri,
                    "code_verifier" to grant.verifier,
                ),
            ),
            previous = null,
            expectedNonce = grant.nonce,
        )

    suspend fun refresh(previous: MultiplatformOidcTokenSet): MultiplatformOidcTokenSet {
        val refreshToken =
            previous.refreshToken
                ?: throw MultiplatformOidcFailure(AuthError.InvalidCredentials("The OIDC session has no refresh token"))
        return parse(
            http.postForm(
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

    private suspend fun parse(
        response: JsonObject,
        previous: MultiplatformOidcTokenSet?,
        expectedNonce: String?,
    ): MultiplatformOidcTokenSet {
        val tokenType = response.requiredMultiplatformString("token_type")
        if (!tokenType.equals("Bearer", ignoreCase = true)) {
            throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC returned an unsupported token type"))
        }
        val idToken =
            response.optionalMultiplatformString("id_token")?.let { verifier.verify(it, expectedNonce) }
                ?: previous?.idToken
                ?: throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC token response omitted id_token"))
        if (previous != null &&
            (idToken.issuer != previous.idToken.issuer || idToken.subject != previous.idToken.subject)
        ) {
            throw MultiplatformOidcFailure(
                AuthError.InvalidCredentials("OIDC refresh response changed the authenticated identity"),
            )
        }
        val expiresIn = response["expires_in"]?.jsonPrimitive?.longOrNull
        if (expiresIn != null && expiresIn <= 0) {
            throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC returned an invalid access token lifetime"))
        }
        return MultiplatformOidcTokenSet(
            accessToken = response.requiredMultiplatformString("access_token"),
            refreshToken = response.optionalMultiplatformString("refresh_token") ?: previous?.refreshToken,
            idToken = idToken,
            accessTokenExpiresAtEpochMillis = expiresIn?.let { nowEpochMillis() + it * 1_000 },
        )
    }
}

internal fun MultiplatformOidcTokenSet.serializeMultiplatform(configuration: OidcConfiguration): ByteArray =
    buildJsonObject {
        put("client_id", JsonPrimitive(configuration.clientId))
        put("discovery_url", JsonPrimitive(configuration.discoveryUrl))
        put("access_token", JsonPrimitive(accessToken))
        refreshToken?.let { put("refresh_token", JsonPrimitive(it)) }
        put("id_token", JsonPrimitive(idToken.raw))
        accessTokenExpiresAtEpochMillis?.let { put("expires_at", JsonPrimitive(it)) }
    }.toString().encodeToByteArray()

internal fun deserializeMultiplatformTokenSet(
    value: ByteArray,
    configuration: OidcConfiguration,
): MultiplatformOidcTokenSet {
    val json =
        runCatching { multiplatformOidcJson.parseToJsonElement(value.decodeToString()).jsonObject }
            .getOrElse {
                throw MultiplatformOidcFailure(AuthError.InvalidCredentials("Stored OIDC session is malformed"), it)
            }
    if (json.requiredMultiplatformString("client_id") != configuration.clientId ||
        json.requiredMultiplatformString("discovery_url") != configuration.discoveryUrl
    ) {
        throw MultiplatformOidcFailure(
            AuthError.InvalidCredentials("Stored OIDC session belongs to another configuration"),
        )
    }
    return MultiplatformOidcTokenSet(
        accessToken = json.requiredMultiplatformString("access_token"),
        refreshToken = json.optionalMultiplatformString("refresh_token"),
        idToken = decodeMultiplatformIdTokenWithoutVerification(json.requiredMultiplatformString("id_token")),
        accessTokenExpiresAtEpochMillis = json["expires_at"]?.jsonPrimitive?.longOrNull,
    )
}
