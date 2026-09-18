@file:Suppress("MagicNumber", "MaxLineLength", "ThrowsCount", "TooGenericExceptionCaught")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.isSuccess
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal val multiplatformOidcJson: Json = Json { ignoreUnknownKeys = true }

internal data class MultiplatformOidcMetadata(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val jwksUri: String,
    val supportedAlgorithms: Set<String>,
)

internal class MultiplatformOidcHttpClient(
    private val client: HttpClient = defaultMultiplatformOidcHttpClient(),
) : AutoCloseable {
    suspend fun discover(configuration: OidcConfiguration): MultiplatformOidcMetadata {
        requireSecure(configuration.discoveryUrl, configuration.allowInsecureHttpForTesting, "discoveryUrl")
        val document = getJson(configuration.discoveryUrl)
        val issuer = document.requiredMultiplatformString("issuer")
        val authorizationEndpoint = document.requiredMultiplatformString("authorization_endpoint")
        val tokenEndpoint = document.requiredMultiplatformString("token_endpoint")
        val jwksUri = document.requiredMultiplatformString("jwks_uri")
        requireSecure(issuer, configuration.allowInsecureHttpForTesting, "issuer")
        requireSecure(authorizationEndpoint, configuration.allowInsecureHttpForTesting, "authorization_endpoint")
        requireSecure(tokenEndpoint, configuration.allowInsecureHttpForTesting, "token_endpoint")
        requireSecure(jwksUri, configuration.allowInsecureHttpForTesting, "jwks_uri")
        return MultiplatformOidcMetadata(
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

    suspend fun getJson(url: String): JsonObject = networkCall { parseSuccess(client.get(url), tokenRequest = false) }

    suspend fun postForm(
        url: String,
        fields: List<Pair<String, String>>,
    ): JsonObject {
        val parameters = Parameters.build { fields.forEach { (name, value) -> append(name, value) } }
        return networkCall {
            parseSuccess(
                client.post(url) { setBody(FormDataContent(parameters)) },
                tokenRequest = true,
            )
        }
    }

    override fun close() {
        client.close()
    }

    private suspend fun parseSuccess(
        response: HttpResponse,
        tokenRequest: Boolean,
    ): JsonObject {
        val body = response.readLimitedBody()
        val json = runCatching { multiplatformOidcJson.parseToJsonElement(body).jsonObject }.getOrNull()
        if (!response.status.isSuccess() || (tokenRequest && json?.get("error") != null)) {
            val code = json?.optionalMultiplatformString("error")
            val description = json?.optionalMultiplatformString("error_description")
            val fallback = "OIDC request failed with HTTP ${response.status.value}"
            throw MultiplatformOidcFailure(
                if (tokenRequest) oidcProtocolError(code, description ?: fallback) else AuthError.Network(fallback),
            )
        }
        return json
            ?: throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC returned malformed JSON"))
    }

    private suspend fun <T> networkCall(block: suspend () -> T): T =
        try {
            block()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: MultiplatformOidcFailure) {
            throw failure
        } catch (failure: Throwable) {
            throw MultiplatformOidcFailure(
                AuthError.Network(failure.message ?: "OIDC network request failed"),
                failure,
            )
        }
}

private suspend fun HttpResponse.readLimitedBody(): String {
    val channel = bodyAsChannel()
    val bytes = ByteArray(MAX_HTTP_RESPONSE_BYTES + 1)
    var total = 0
    while (total < bytes.size) {
        val read = channel.readAvailable(bytes, total, bytes.size - total)
        if (read < 0) break
        total += read
    }
    if (total > MAX_HTTP_RESPONSE_BYTES) {
        channel.cancel(null)
        throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC response exceeded the size limit"))
    }
    return bytes.decodeToString(endIndex = total)
}

private fun defaultMultiplatformOidcHttpClient(): HttpClient =
    HttpClient {
        expectSuccess = false
        followRedirects = false
        install(HttpTimeout) {
            requestTimeoutMillis = HTTP_TIMEOUT_MILLIS
            connectTimeoutMillis = HTTP_TIMEOUT_MILLIS
            socketTimeoutMillis = HTTP_TIMEOUT_MILLIS
        }
    }

internal fun JsonObject.requiredMultiplatformString(name: String): String =
    optionalMultiplatformString(name)?.takeIf(String::isNotBlank)
        ?: throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC response omitted $name"))

internal fun JsonObject.optionalMultiplatformString(name: String): String? =
    this[name]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }

internal fun requireSecure(
    value: String,
    allowInsecureHttpForTesting: Boolean,
    name: String,
) {
    val url = runCatching { Url(value) }.getOrElse { throw IllegalArgumentException("$name must be an absolute URL", it) }
    val isHttps = url.protocol.name.equals("https", ignoreCase = true)
    val allowedTestHttp =
        allowInsecureHttpForTesting &&
            url.protocol.name.equals("http", ignoreCase = true) &&
            (url.host == "127.0.0.1" || url.host == "::1" || url.host == "[::1]")
    require(isHttps || allowedTestHttp) { "$name must use HTTPS" }
    require(url.host.isNotBlank()) { "$name must include a host" }
    require(url.user == null && url.password == null && url.fragment.isEmpty()) {
        "$name must not include user info or a fragment"
    }
}

internal class MultiplatformOidcFailure(
    val error: AuthError,
    cause: Throwable? = null,
) : Exception(error.message, cause)

internal fun oidcProtocolError(
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

private const val HTTP_TIMEOUT_MILLIS = 30_000L
private const val MAX_HTTP_RESPONSE_BYTES = 1024 * 1024
