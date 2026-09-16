@file:Suppress("MagicNumber", "MaxLineLength")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

internal val oidcJson: Json = Json { ignoreUnknownKeys = true }

internal data class OidcMetadata(
    val issuer: String,
    val authorizationEndpoint: URI,
    val tokenEndpoint: URI,
    val jwksUri: URI,
    val supportedAlgorithms: Set<String>,
)

internal fun discover(configuration: OidcConfiguration): OidcMetadata {
    val discoveryUri = URI(configuration.discoveryUrl)
    discoveryUri.requireSecure(configuration.allowInsecureHttpForTesting, "discoveryUrl")
    val document = httpJson(discoveryUri)
    val issuer = document.requiredString("issuer")
    URI(issuer).requireSecure(configuration.allowInsecureHttpForTesting, "issuer")
    val authorizationEndpoint = URI(document.requiredString("authorization_endpoint"))
    val tokenEndpoint = URI(document.requiredString("token_endpoint"))
    val jwksUri = URI(document.requiredString("jwks_uri"))
    authorizationEndpoint.requireSecure(configuration.allowInsecureHttpForTesting, "authorization_endpoint")
    tokenEndpoint.requireSecure(configuration.allowInsecureHttpForTesting, "token_endpoint")
    jwksUri.requireSecure(configuration.allowInsecureHttpForTesting, "jwks_uri")
    return OidcMetadata(
        issuer = issuer,
        authorizationEndpoint = authorizationEndpoint,
        tokenEndpoint = tokenEndpoint,
        jwksUri = jwksUri,
        supportedAlgorithms =
            document["id_token_signing_alg_values_supported"]
                ?.let { element ->
                    runCatching { element.jsonArray.map { it.jsonPrimitive.content }.toSet() }.getOrNull()
                }.orEmpty(),
    )
}

internal fun httpJson(uri: URI): JsonObject {
    val connection = uri.toURL().openConnection() as HttpURLConnection
    return try {
        connection.connectTimeout = HTTP_TIMEOUT_MILLIS
        connection.readTimeout = HTTP_TIMEOUT_MILLIS
        connection.instanceFollowRedirects = false
        connection.setRequestProperty("Accept", "application/json")
        val status = connection.responseCode
        val body = connection.readBody(status)
        if (status !in 200..299) {
            throw OidcFailure(AuthError.Network("OIDC request failed with HTTP $status"))
        }
        runCatching { oidcJson.parseToJsonElement(body).jsonObject }
            .getOrElse { throw OidcFailure(AuthError.InvalidCredentials("OIDC returned malformed JSON"), it) }
    } finally {
        connection.disconnect()
    }
}

internal fun postForm(
    uri: URI,
    fields: List<Pair<String, String>>,
): JsonObject {
    val connection = uri.toURL().openConnection() as HttpURLConnection
    return try {
        connection.requestMethod = "POST"
        connection.connectTimeout = HTTP_TIMEOUT_MILLIS
        connection.readTimeout = HTTP_TIMEOUT_MILLIS
        connection.instanceFollowRedirects = false
        connection.doOutput = true
        connection.setRequestProperty("Accept", "application/json")
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
        val body = fields.formEncode().toByteArray(StandardCharsets.UTF_8)
        connection.outputStream.use { it.write(body) }
        val status = connection.responseCode
        val responseBody = connection.readBody(status)
        val json = runCatching { oidcJson.parseToJsonElement(responseBody).jsonObject }.getOrNull()
        if (status !in 200..299 || json?.get("error") != null) {
            val code = json?.optionalString("error")
            val description = json?.optionalString("error_description")
            throw OidcFailure(oauthError(code, description ?: "OIDC token request failed with HTTP $status"))
        }
        json ?: throw OidcFailure(AuthError.InvalidCredentials("OIDC returned malformed token JSON"))
    } finally {
        connection.disconnect()
    }
}

internal fun List<Pair<String, String>>.formEncode(): String =
    joinToString("&") { (name, value) -> "${name.urlEncode()}=${value.urlEncode()}" }

internal fun JsonObject.requiredString(name: String): String =
    optionalString(name)?.takeIf(String::isNotBlank)
        ?: throw OidcFailure(AuthError.InvalidCredentials("OIDC response omitted $name"))

internal fun JsonObject.optionalString(name: String): String? = this[name]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }

internal fun URI.requireSecure(
    allowInsecureHttpForTesting: Boolean,
    name: String,
) {
    val isHttps = scheme.equals("https", ignoreCase = true)
    val allowedTestHttp =
        allowInsecureHttpForTesting &&
            scheme.equals("http", ignoreCase = true) &&
            (host == "127.0.0.1" || host == "::1" || host == "[::1]")
    require(isHttps || allowedTestHttp) { "$name must use HTTPS" }
    require(!host.isNullOrBlank()) { "$name must include a host" }
    require(userInfo == null && fragment == null) { "$name must not include user info or a fragment" }
}

internal class OidcFailure(
    val error: AuthError,
    cause: Throwable? = null,
) : Exception(error.message, cause)

internal fun oauthError(
    code: String?,
    message: String,
): AuthError =
    when (code) {
        "access_denied" -> AuthError.Cancelled(message, code)
        "invalid_grant" -> AuthError.InvalidCredentials(message, code)
        "invalid_client", "unauthorized_client" -> AuthError.ProviderDisabled(message, code)
        "temporarily_unavailable", "server_error" -> AuthError.Network(message, code)
        else -> AuthError.Unknown(message, code)
    }

private fun HttpURLConnection.readBody(status: Int): String =
    (if (status in 200..299) inputStream else errorStream)
        ?.use { stream ->
            val bytes = stream.readNBytes(MAX_HTTP_RESPONSE_BYTES + 1)
            if (bytes.size > MAX_HTTP_RESPONSE_BYTES) {
                throw OidcFailure(AuthError.InvalidCredentials("OIDC response exceeded the size limit"))
            }
            String(bytes, StandardCharsets.UTF_8)
        }.orEmpty()

private fun String.urlEncode(): String = URLEncoder.encode(this, StandardCharsets.UTF_8.name())

private const val HTTP_TIMEOUT_MILLIS = 30_000
private const val MAX_HTTP_RESPONSE_BYTES = 1024 * 1024
