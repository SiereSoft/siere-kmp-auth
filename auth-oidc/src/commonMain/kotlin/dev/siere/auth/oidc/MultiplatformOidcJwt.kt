@file:Suppress("CyclomaticComplexMethod", "MagicNumber", "MaxLineLength", "ReturnCount", "TooManyFunctions")

package dev.siere.auth.oidc

import dev.siere.auth.AuthError
import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.Digest
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlin.time.Clock

internal data class MultiplatformVerifiedIdToken(
    val raw: String,
    val issuer: String,
    val subject: String,
    val audiences: List<String>,
    val expiresAtEpochSeconds: Long,
    val issuedAtEpochSeconds: Long,
    val claims: JsonObject,
)

internal class MultiplatformOidcIdTokenVerifier(
    private val metadata: MultiplatformOidcMetadata,
    private val clientId: String,
    private val clockSkewSeconds: Long,
    private val allowInsecureHttpForTesting: Boolean,
    private val http: MultiplatformOidcHttpClient,
    private val nowEpochSeconds: () -> Long = { Clock.System.now().epochSeconds },
) {
    private var cachedKeys: List<JsonObject> = emptyList()

    suspend fun verify(
        token: String,
        expectedNonce: String?,
    ): MultiplatformVerifiedIdToken {
        if (token.length > MAX_ID_TOKEN_CHARACTERS) invalidMultiplatformToken("ID token is too large")
        val parts = token.split('.')
        if (parts.size != 3) invalidMultiplatformToken("ID token is not a JWT")
        val header = parts[0].decodeMultiplatformJson()
        val algorithm = header.requiredMultiplatformString("alg")
        if (algorithm == "none" || algorithm !in SUPPORTED_ALGORITHMS) {
            invalidMultiplatformToken("ID token uses unsupported algorithm $algorithm")
        }
        if (metadata.supportedAlgorithms.isNotEmpty() && algorithm !in metadata.supportedAlgorithms) {
            invalidMultiplatformToken("ID token algorithm was not advertised by the provider")
        }
        val keyId = header.optionalMultiplatformString("kid")
        val data = "${parts[0]}.${parts[1]}".encodeToByteArray()
        val signature = parts[2].decodeMultiplatformBase64UrlSafely()
        if (algorithm.startsWith("ES") && signature.size != algorithm.ecSignatureBytes) {
            invalidMultiplatformToken("ID token ECDSA signature has invalid length")
        }
        if (!verifyWithCachedKeys(keyId, algorithm, data, signature)) {
            cachedKeys = loadKeys()
            if (!verifyWithCachedKeys(keyId, algorithm, data, signature)) {
                invalidMultiplatformToken("ID token signature is invalid")
            }
        }

        val claims = parts[1].decodeMultiplatformJson()
        val issuer = claims.requiredMultiplatformString("iss")
        if (issuer != metadata.issuer) invalidMultiplatformToken("ID token issuer is invalid")
        val subject = claims.requiredMultiplatformString("sub")
        if (subject.isBlank()) invalidMultiplatformToken("ID token subject is invalid")
        val audiences = claims.multiplatformAudiences()
        if (clientId !in audiences) invalidMultiplatformToken("ID token audience is invalid")
        if (audiences.size > 1 && claims.optionalMultiplatformString("azp") != clientId) {
            invalidMultiplatformToken("ID token authorized party is invalid")
        }
        val now = nowEpochSeconds()
        val expiresAt = claims.requiredMultiplatformLong("exp")
        val issuedAt = claims.requiredMultiplatformLong("iat")
        val notBefore = claims.optionalMultiplatformLong("nbf")
        if (expiresAt <= now - clockSkewSeconds) invalidMultiplatformToken("ID token has expired")
        if (issuedAt > now + clockSkewSeconds) invalidMultiplatformToken("ID token was issued in the future")
        if (notBefore != null && notBefore > now + clockSkewSeconds) {
            invalidMultiplatformToken("ID token is not active yet")
        }
        if (expectedNonce != null && claims.optionalMultiplatformString("nonce") != expectedNonce) {
            invalidMultiplatformToken("ID token nonce is invalid")
        }
        return MultiplatformVerifiedIdToken(token, issuer, subject, audiences, expiresAt, issuedAt, claims)
    }

    private suspend fun verifyWithCachedKeys(
        keyId: String?,
        algorithm: String,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val candidates =
            cachedKeys.filter { jwk ->
                (keyId == null || jwk.optionalMultiplatformString("kid") == keyId) &&
                    (jwk.optionalMultiplatformString("use") == null || jwk.optionalMultiplatformString("use") == "sig") &&
                    jwk.allowsMultiplatformSignatureVerification() &&
                    (jwk.optionalMultiplatformString("alg") == null || jwk.optionalMultiplatformString("alg") == algorithm)
            }
        if (keyId == null && candidates.size != 1) return false
        for (jwk in candidates) {
            val verified =
                try {
                    verifySignature(jwk, algorithm, data, signature)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Throwable) {
                    false
                }
            if (verified) return true
        }
        return false
    }

    private suspend fun verifySignature(
        jwk: JsonObject,
        algorithm: String,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val digest = algorithm.multiplatformDigest
        return when {
            algorithm.startsWith("RS") && jwk.requiredMultiplatformString("kty") == "RSA" -> {
                val modulus = jwk.requiredMultiplatformString("n").decodeMultiplatformBase64UrlSafely()
                require(modulus.multiplatformBitLength() >= MINIMUM_RSA_BITS) {
                    "RSA signing key is too small"
                }
                val key =
                    CryptographyProvider.Default
                        .get(RSA.PKCS1)
                        .publicKeyDecoder(digest)
                        .decodeFromByteArray(RSA.PublicKey.Format.JWK, jwk.toString().encodeToByteArray())
                key.signatureVerifier().tryVerifySignature(data, signature)
            }

            algorithm.startsWith("ES") && jwk.requiredMultiplatformString("kty") == "EC" -> {
                val curve = algorithm.multiplatformCurve
                require(jwk.requiredMultiplatformString("crv") == curve.name) {
                    "JWK curve does not match ID token algorithm"
                }
                val key =
                    CryptographyProvider.Default
                        .get(ECDSA)
                        .publicKeyDecoder(curve)
                        .decodeFromByteArray(EC.PublicKey.Format.JWK, jwk.toString().encodeToByteArray())
                key.signatureVerifier(digest, ECDSA.SignatureFormat.RAW).tryVerifySignature(data, signature)
            }

            else -> false
        }
    }

    private suspend fun loadKeys(): List<JsonObject> {
        requireSecure(metadata.jwksUri, allowInsecureHttpForTesting, "jwks_uri")
        val keys =
            http
                .getJson(metadata.jwksUri)["keys"]
                ?.jsonArray
                ?.map { it.jsonObject }
                .orEmpty()
        if (keys.isEmpty()) {
            throw MultiplatformOidcFailure(AuthError.InvalidCredentials("OIDC provider returned no signing keys"))
        }
        return keys
    }
}

internal fun decodeMultiplatformIdTokenWithoutVerification(token: String): MultiplatformVerifiedIdToken {
    val parts = token.split('.')
    if (parts.size != 3) invalidMultiplatformToken("Stored ID token is not a JWT")
    val claims = parts[1].decodeMultiplatformJson()
    return MultiplatformVerifiedIdToken(
        raw = token,
        issuer = claims.requiredMultiplatformString("iss"),
        subject = claims.requiredMultiplatformString("sub"),
        audiences = claims.multiplatformAudiences(),
        expiresAtEpochSeconds = claims.requiredMultiplatformLong("exp"),
        issuedAtEpochSeconds = claims.requiredMultiplatformLong("iat"),
        claims = claims,
    )
}

internal fun MultiplatformVerifiedIdToken.claimString(name: String): String? = claims.optionalMultiplatformString(name)

internal fun MultiplatformVerifiedIdToken.claimBoolean(name: String): Boolean = claims[name]?.jsonPrimitive?.booleanOrNull == true

private fun JsonObject.allowsMultiplatformSignatureVerification(): Boolean =
    this["key_ops"]
        ?.let { value ->
            runCatching { value.jsonArray.map { it.jsonPrimitive.content }.contains("verify") }.getOrDefault(false)
        } ?: true

private fun JsonObject.multiplatformAudiences(): List<String> {
    val value = this["aud"] ?: invalidMultiplatformToken("ID token omitted aud")
    return runCatching { listOf(value.jsonPrimitive.content) }
        .getOrElse { value.jsonArray.map { it.jsonPrimitive.content } }
        .also { if (it.isEmpty() || it.any(String::isBlank)) invalidMultiplatformToken("ID token audience is invalid") }
}

private fun JsonObject.requiredMultiplatformLong(name: String): Long =
    optionalMultiplatformLong(name) ?: invalidMultiplatformToken("ID token omitted $name")

private fun JsonObject.optionalMultiplatformLong(name: String): Long? = this[name]?.jsonPrimitive?.longOrNull

private fun String.decodeMultiplatformJson(): JsonObject =
    runCatching {
        multiplatformOidcJson.parseToJsonElement(decodeMultiplatformBase64Url().decodeToString()).jsonObject
    }.getOrElse { invalidMultiplatformToken("ID token contains malformed JSON") }

private fun String.decodeMultiplatformBase64UrlSafely(): ByteArray =
    runCatching { decodeMultiplatformBase64Url() }
        .getOrElse { invalidMultiplatformToken("ID token contains invalid base64url") }

private fun ByteArray.multiplatformBitLength(): Int {
    val firstNonZero = indexOfFirst { it != 0.toByte() }
    if (firstNonZero < 0) return 0
    val first = this[firstNonZero].toInt() and 0xff
    val firstBits = 32 - first.countLeadingZeroBits()
    return (size - firstNonZero - 1) * 8 + firstBits
}

private val String.multiplatformDigest: CryptographyAlgorithmId<Digest>
    get() =
        when (this) {
            "RS256", "ES256" -> SHA256
            "RS384", "ES384" -> SHA384
            "RS512", "ES512" -> SHA512
            else -> error("Unsupported signing algorithm")
        }

private val String.multiplatformCurve: EC.Curve
    get() =
        when (this) {
            "ES256" -> EC.Curve.P256
            "ES384" -> EC.Curve.P384
            "ES512" -> EC.Curve.P521
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

private fun invalidMultiplatformToken(message: String): Nothing = throw MultiplatformOidcFailure(AuthError.InvalidCredentials(message))

private val SUPPORTED_ALGORITHMS = setOf("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
private const val MAX_ID_TOKEN_CHARACTERS = 64 * 1024
private const val MINIMUM_RSA_BITS = 2_048
