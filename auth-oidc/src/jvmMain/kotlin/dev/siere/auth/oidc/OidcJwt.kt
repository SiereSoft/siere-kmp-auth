@file:Suppress("CyclomaticComplexMethod", "MagicNumber", "ReturnCount", "TooManyFunctions")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.time.Clock
import java.util.Base64

internal data class VerifiedIdToken(
    val raw: String,
    val issuer: String,
    val subject: String,
    val audiences: List<String>,
    val expiresAtEpochSeconds: Long,
    val issuedAtEpochSeconds: Long,
    val claims: JsonObject,
)

internal class OidcIdTokenVerifier(
    private val metadata: OidcMetadata,
    private val clientId: String,
    private val clockSkewSeconds: Long,
    private val allowInsecureHttpForTesting: Boolean,
    private val clock: Clock = Clock.systemUTC(),
) {
    @Volatile
    private var cachedKeys: List<JsonObject> = emptyList()

    fun verify(
        token: String,
        expectedNonce: String?,
    ): VerifiedIdToken {
        if (token.length > MAX_ID_TOKEN_CHARACTERS) invalid("ID token is too large")
        val parts = token.split('.')
        if (parts.size != 3) invalid("ID token is not a JWT")
        val header = parts[0].decodeJson()
        val algorithm = header.requiredString("alg")
        if (algorithm == "none" || algorithm !in SUPPORTED_ALGORITHMS) {
            invalid("ID token uses unsupported algorithm $algorithm")
        }
        if (metadata.supportedAlgorithms.isNotEmpty() && algorithm !in metadata.supportedAlgorithms) {
            invalid("ID token algorithm was not advertised by the provider")
        }
        val keyId = header.optionalString("kid")
        val key = findKey(keyId, algorithm)
        val signature = parts[2].base64UrlBytes()
        if (algorithm.startsWith("ES") && signature.size != algorithm.ecSignatureBytes) {
            invalid("ID token ECDSA signature has invalid length")
        }
        val verified =
            Signature.getInstance(algorithm.javaSignatureName).run {
                initVerify(key)
                update("${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII))
                verify(if (algorithm.startsWith("ES")) signature.joseToDer() else signature)
            }
        if (!verified) invalid("ID token signature is invalid")

        val claims = parts[1].decodeJson()
        val issuer = claims.requiredString("iss")
        if (issuer != metadata.issuer) invalid("ID token issuer is invalid")
        val subject = claims.requiredString("sub")
        if (subject.isBlank()) invalid("ID token subject is invalid")
        val audiences = claims.audiences()
        if (clientId !in audiences) invalid("ID token audience is invalid")
        if (audiences.size > 1 && claims.optionalString("azp") != clientId) {
            invalid("ID token authorized party is invalid")
        }
        val now = clock.instant().epochSecond
        val expiresAt = claims.requiredLong("exp")
        val issuedAt = claims.requiredLong("iat")
        val notBefore = claims.optionalLong("nbf")
        if (expiresAt <= now - clockSkewSeconds) invalid("ID token has expired")
        if (issuedAt > now + clockSkewSeconds) invalid("ID token was issued in the future")
        if (notBefore != null && notBefore > now + clockSkewSeconds) invalid("ID token is not active yet")
        if (expectedNonce != null && claims.optionalString("nonce") != expectedNonce) {
            invalid("ID token nonce is invalid")
        }
        return VerifiedIdToken(token, issuer, subject, audiences, expiresAt, issuedAt, claims)
    }

    private fun findKey(
        keyId: String?,
        algorithm: String,
    ): PublicKey {
        findCachedKey(keyId, algorithm)?.let { return it }
        cachedKeys = loadKeys()
        return findCachedKey(keyId, algorithm)
            ?: throw OidcFailure(AuthError.InvalidCredentials("ID token references an unknown signing key"))
    }

    private fun findCachedKey(
        keyId: String?,
        algorithm: String,
    ): PublicKey? {
        val candidates =
            cachedKeys.filter { jwk ->
                (keyId == null || jwk.optionalString("kid") == keyId) &&
                    (jwk.optionalString("use") == null || jwk.optionalString("use") == "sig") &&
                    jwk.allowsSignatureVerification() &&
                    (jwk.optionalString("alg") == null || jwk.optionalString("alg") == algorithm)
            }
        if (keyId == null && candidates.size != 1) return null
        return candidates.firstNotNullOfOrNull { runCatching { it.toPublicKey(algorithm) }.getOrNull() }
    }

    private fun loadKeys(): List<JsonObject> {
        metadata.jwksUri.requireSecure(allowInsecureHttpForTesting, "jwks_uri")
        val keys = httpJson(metadata.jwksUri)["keys"]?.jsonArray?.map { it.jsonObject }.orEmpty()
        if (keys.isEmpty()) throw OidcFailure(AuthError.InvalidCredentials("OIDC provider returned no signing keys"))
        return keys
    }
}

private fun JsonObject.allowsSignatureVerification(): Boolean =
    this["key_ops"]
        ?.let { value ->
            runCatching { value.jsonArray.map { it.jsonPrimitive.content }.contains("verify") }.getOrDefault(false)
        } ?: true

private fun JsonObject.toPublicKey(algorithm: String): PublicKey =
    when {
        algorithm.startsWith("RS") && requiredString("kty") == "RSA" -> {
            val modulus = BigInteger(1, requiredString("n").base64UrlBytes())
            val exponent = BigInteger(1, requiredString("e").base64UrlBytes())
            require(modulus.bitLength() >= MINIMUM_RSA_BITS) { "RSA signing key is too small" }
            KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
        }

        algorithm.startsWith("ES") && requiredString("kty") == "EC" -> {
            val curve = requiredString("crv")
            val expectedCurve = algorithm.curveName
            require(curve == expectedCurve.first) { "JWK curve does not match ID token algorithm" }
            val parameters =
                AlgorithmParameters.getInstance("EC").run {
                    init(ECGenParameterSpec(expectedCurve.second))
                    getParameterSpec(ECParameterSpec::class.java)
                }
            val point =
                ECPoint(
                    BigInteger(1, requiredString("x").base64UrlBytes()),
                    BigInteger(1, requiredString("y").base64UrlBytes()),
                )
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, parameters))
        }

        else -> error("JWK type does not match ID token algorithm")
    }

internal fun decodeIdTokenWithoutVerification(token: String): VerifiedIdToken {
    val parts = token.split('.')
    if (parts.size != 3) invalid("Stored ID token is not a JWT")
    val claims = parts[1].decodeJson()
    return VerifiedIdToken(
        raw = token,
        issuer = claims.requiredString("iss"),
        subject = claims.requiredString("sub"),
        audiences = claims.audiences(),
        expiresAtEpochSeconds = claims.requiredLong("exp"),
        issuedAtEpochSeconds = claims.requiredLong("iat"),
        claims = claims,
    )
}

internal fun VerifiedIdToken.claimString(name: String): String? = claims.optionalString(name)

internal fun VerifiedIdToken.claimBoolean(name: String): Boolean = claims[name]?.jsonPrimitive?.booleanOrNull == true

private fun JsonObject.audiences(): List<String> {
    val value = this["aud"] ?: invalid("ID token omitted aud")
    return runCatching { listOf(value.jsonPrimitive.content) }
        .getOrElse { value.jsonArray.map { it.jsonPrimitive.content } }
        .also { if (it.isEmpty() || it.any(String::isBlank)) invalid("ID token audience is invalid") }
}

private fun JsonObject.requiredLong(name: String): Long = optionalLong(name) ?: invalid("ID token omitted $name")

private fun JsonObject.optionalLong(name: String): Long? = this[name]?.jsonPrimitive?.longOrNull

private fun String.decodeJson(): JsonObject =
    runCatching { oidcJson.parseToJsonElement(String(base64UrlBytes(), StandardCharsets.UTF_8)).jsonObject }
        .getOrElse { invalid("ID token contains malformed JSON") }

private fun String.base64UrlBytes(): ByteArray =
    runCatching { Base64.getUrlDecoder().decode(this) }.getOrElse { invalid("ID token contains invalid base64url") }

private val String.javaSignatureName: String
    get() =
        when (this) {
            "RS256" -> "SHA256withRSA"
            "RS384" -> "SHA384withRSA"
            "RS512" -> "SHA512withRSA"
            "ES256" -> "SHA256withECDSA"
            "ES384" -> "SHA384withECDSA"
            "ES512" -> "SHA512withECDSA"
            else -> error("Unsupported signing algorithm")
        }

private val String.curveName: Pair<String, String>
    get() =
        when (this) {
            "ES256" -> "P-256" to "secp256r1"
            "ES384" -> "P-384" to "secp384r1"
            "ES512" -> "P-521" to "secp521r1"
            else -> error("Unsupported EC algorithm")
        }

private val String.ecSignatureBytes: Int
    get() =
        when (this) {
            "ES256" -> 64
            "ES384" -> 96
            "ES512" -> 132
            else -> error("Unsupported EC algorithm")
        }

private fun ByteArray.joseToDer(): ByteArray {
    require(size % 2 == 0) { "ECDSA signature has invalid length" }
    val coordinateSize = size / 2
    val r = copyOfRange(0, coordinateSize).derInteger()
    val s = copyOfRange(coordinateSize, size).derInteger()
    val body = byteArrayOf(0x02) + r.derLength() + r + byteArrayOf(0x02) + s.derLength() + s
    return byteArrayOf(0x30) + body.derLength() + body
}

private fun ByteArray.derInteger(): ByteArray {
    val withoutLeadingZeros = dropWhile { it == 0.toByte() }.toByteArray()
    val trimmed = if (withoutLeadingZeros.isEmpty()) byteArrayOf(0) else withoutLeadingZeros
    return if (trimmed[0].toInt() and 0x80 != 0) byteArrayOf(0) + trimmed else trimmed
}

private fun ByteArray.derLength(): ByteArray =
    if (size < 128) {
        byteArrayOf(size.toByte())
    } else {
        val bytes =
            BigInteger
                .valueOf(size.toLong())
                .toByteArray()
                .dropWhile { it == 0.toByte() }
                .toByteArray()
        byteArrayOf((0x80 or bytes.size).toByte()) + bytes
    }

private fun invalid(message: String): Nothing = throw OidcFailure(AuthError.InvalidCredentials(message))

private val SUPPORTED_ALGORITHMS = setOf("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
private const val MAX_ID_TOKEN_CHARACTERS = 64 * 1024
private const val MINIMUM_RSA_BITS = 2_048
