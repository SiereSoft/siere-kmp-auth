@file:Suppress("LongMethod", "MagicNumber", "MaxLineLength")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.random.CryptographyRandom
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

internal data class MultiplatformOidcAuthorizationGrant(
    val code: String,
    val verifier: String,
    val nonce: String,
    val redirectUri: String,
)

internal class MultiplatformOidcAuthorizationFlow(
    private val configuration: OidcConfiguration,
    private val redirectUri: String,
    private val authorizationHandler: OidcAuthorizationHandler,
) {
    private val operations = Mutex()

    init {
        require(ABSOLUTE_URI_SCHEME.containsMatchIn(redirectUri)) { "redirectUri must be absolute" }
        val parsed = runCatching { Url(redirectUri) }.getOrElse { throw IllegalArgumentException("redirectUri is invalid", it) }
        require(parsed.parameters.isEmpty() && parsed.fragment.isEmpty()) {
            "redirectUri must not contain a query or fragment"
        }
    }

    suspend fun authorize(metadata: MultiplatformOidcMetadata): MultiplatformOidcAuthorizationGrant =
        operations.withLock {
            val verifier = secureRandomValue(32)
            val challenge =
                CryptographyProvider.Default
                    .get(SHA256)
                    .hasher()
                    .hash(verifier.encodeToByteArray())
                    .encodeMultiplatformBase64Url()
            val state = secureRandomValue(32)
            val nonce = secureRandomValue(32)
            val authorizationUrl =
                URLBuilder(metadata.authorizationEndpoint)
                    .apply {
                        parameters.append("client_id", configuration.clientId)
                        parameters.append("redirect_uri", redirectUri)
                        parameters.append("response_type", "code")
                        parameters.append("scope", (configuration.scopes + "openid").joinToString(" "))
                        parameters.append("code_challenge", challenge)
                        parameters.append("code_challenge_method", "S256")
                        parameters.append("state", state)
                        parameters.append("nonce", nonce)
                        configuration.additionalAuthorizationParameters.forEach { (name, value) ->
                            parameters.append(name, value)
                        }
                    }.buildString()
            val callback =
                withTimeoutOrNull(configuration.callbackTimeoutMillis) {
                    authorizationHandler.authorize(OidcAuthorizationRequest(authorizationUrl, redirectUri))
                } ?: throw MultiplatformOidcFailure(
                    AuthError.Network("Timed out waiting for the OIDC callback", "timeout"),
                )
            if (callback.substringBefore('?').substringBefore('#') != redirectUri) {
                throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC callback URI is invalid"))
            }
            val callbackUrl =
                runCatching { Url(callback) }
                    .getOrElse {
                        throw MultiplatformOidcFailure(
                            AuthError.InvalidCredentials("OIDC callback URL is malformed"),
                            it,
                        )
                    }
            if (callbackUrl.fragment.isNotEmpty()) {
                throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC callback URI is invalid"))
            }
            val parameters = callbackUrl.parameters
            if (parameters.singleCallbackValue("state") != state) {
                throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC callback state is invalid"))
            }
            parameters.singleCallbackValue("error")?.let { code ->
                throw MultiplatformOidcFailure(
                    oidcProtocolError(
                        code,
                        parameters.singleCallbackValue("error_description") ?: "OIDC authorization failed",
                    ),
                )
            }
            parameters.singleCallbackValue("iss")?.let { issuer ->
                if (issuer != metadata.issuer) {
                    throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC callback issuer is invalid"))
                }
            }
            val code =
                parameters.singleCallbackValue("code")?.takeIf(String::isNotBlank)
                    ?: throw MultiplatformOidcFailure(
                        AuthError.InvalidCredentials("OIDC callback omitted the authorization code"),
                    )
            MultiplatformOidcAuthorizationGrant(code, verifier, nonce, redirectUri)
        }
}

private fun io.ktor.http.Parameters.singleCallbackValue(name: String): String? {
    val values = getAll(name).orEmpty()
    if (values.size > 1) {
        throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC callback repeated $name"))
    }
    return values.singleOrNull()
}

internal fun secureRandomValue(byteCount: Int): String = CryptographyRandom.nextBytes(byteCount).encodeMultiplatformBase64Url()

internal fun ByteArray.encodeMultiplatformBase64Url(): String {
    if (isEmpty()) return ""
    val result = StringBuilder((size * 4 + 2) / 3)
    var index = 0
    while (index + 2 < size) {
        val value =
            ((this[index].toInt() and 0xff) shl 16) or
                ((this[index + 1].toInt() and 0xff) shl 8) or
                (this[index + 2].toInt() and 0xff)
        result.append(BASE64_URL_ALPHABET[(value ushr 18) and 63])
        result.append(BASE64_URL_ALPHABET[(value ushr 12) and 63])
        result.append(BASE64_URL_ALPHABET[(value ushr 6) and 63])
        result.append(BASE64_URL_ALPHABET[value and 63])
        index += 3
    }
    val remaining = size - index
    if (remaining == 1) {
        val value = (this[index].toInt() and 0xff) shl 16
        result.append(BASE64_URL_ALPHABET[(value ushr 18) and 63])
        result.append(BASE64_URL_ALPHABET[(value ushr 12) and 63])
    } else if (remaining == 2) {
        val value = ((this[index].toInt() and 0xff) shl 16) or ((this[index + 1].toInt() and 0xff) shl 8)
        result.append(BASE64_URL_ALPHABET[(value ushr 18) and 63])
        result.append(BASE64_URL_ALPHABET[(value ushr 12) and 63])
        result.append(BASE64_URL_ALPHABET[(value ushr 6) and 63])
    }
    return result.toString()
}

internal fun String.decodeMultiplatformBase64Url(): ByteArray {
    require(length % 4 != 1) { "Invalid base64url length" }
    val output = ByteArray(length * 6 / 8)
    var accumulator = 0
    var bitCount = 0
    var outputIndex = 0
    for (character in this) {
        val value = BASE64_URL_ALPHABET.indexOf(character)
        require(value >= 0) { "Invalid base64url character" }
        accumulator = (accumulator shl 6) or value
        bitCount += 6
        if (bitCount >= 8) {
            bitCount -= 8
            output[outputIndex++] = (accumulator ushr bitCount).toByte()
            accumulator = accumulator and ((1 shl bitCount) - 1)
        }
    }
    require(bitCount == 0 || accumulator == 0) { "Invalid base64url padding bits" }
    return output
}

private const val BASE64_URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
private val ABSOLUTE_URI_SCHEME = Regex("^[A-Za-z][A-Za-z0-9+.-]*:")
