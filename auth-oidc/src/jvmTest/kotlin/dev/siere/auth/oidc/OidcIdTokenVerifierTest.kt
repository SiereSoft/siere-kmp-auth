@file:Suppress("LongParameterList", "MagicNumber", "MaxLineLength")

package dev.siere.auth.oidc

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class OidcIdTokenVerifierTest {
    private val now = Instant.parse("2026-01-02T03:04:05Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun validatesClaimsAndReloadsJwksForKeyRotation() {
        val first = rsaKeyPair()
        val second = rsaKeyPair()
        val currentKey = AtomicReference("first" to first)
        val server = jwksServer(currentKey)
        try {
            val verifier = verifier(server)
            assertEquals("subject", verifier.verify(token(first, "first", validClaims()), "nonce").subject)

            currentKey.set("second" to second)
            assertEquals("subject", verifier.verify(token(second, "second", validClaims()), "nonce").subject)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun rejectsInvalidSignatureIssuerAudienceTimeNonceAndAuthorizedParty() {
        val trusted = rsaKeyPair()
        val attacker = rsaKeyPair()
        val currentKey = AtomicReference("trusted" to trusted)
        val server = jwksServer(currentKey)
        try {
            val verifier = verifier(server)
            val invalidTokens =
                listOf(
                    token(attacker, "trusted", validClaims()),
                    token(trusted, "trusted", validClaims(issuer = "https://other.example")),
                    token(trusted, "trusted", validClaims(audience = "other-client")),
                    token(trusted, "trusted", validClaims(exp = now.epochSecond - 31)),
                    token(trusted, "trusted", validClaims(iat = now.epochSecond + 31)),
                    token(trusted, "trusted", validClaims(nbf = now.epochSecond + 31)),
                    token(trusted, "trusted", validClaims(nonce = "wrong")),
                    token(
                        trusted,
                        "trusted",
                        validClaims(audience = "[\"desktop-client\",\"another\"]", audienceIsJson = true),
                    ),
                )

            invalidTokens.forEach { value ->
                assertFailsWith<OidcFailure> { verifier.verify(value, "nonce") }
            }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun acceptsMultipleAudiencesOnlyWithMatchingAuthorizedParty() {
        val key = rsaKeyPair()
        val currentKey = AtomicReference("trusted" to key)
        val server = jwksServer(currentKey)
        try {
            val claims =
                validClaims(
                    audience = "[\"desktop-client\",\"another\"]",
                    audienceIsJson = true,
                    extra = "\"azp\":\"desktop-client\",",
                )

            assertEquals("subject", verifier(server).verify(token(key, "trusted", claims), "nonce").subject)
        } finally {
            server.stop(0)
        }
    }

    private fun verifier(server: HttpServer): OidcIdTokenVerifier {
        val issuer = "https://issuer.example"
        return OidcIdTokenVerifier(
            metadata =
                OidcMetadata(
                    issuer = issuer,
                    authorizationEndpoint = URI("https://issuer.example/authorize"),
                    tokenEndpoint = URI("https://issuer.example/token"),
                    jwksUri = URI("http://127.0.0.1:${server.address.port}/jwks"),
                    supportedAlgorithms = setOf("RS256"),
                ),
            clientId = "desktop-client",
            clockSkewSeconds = 30,
            allowInsecureHttpForTesting = true,
            clock = clock,
        )
    }

    private fun validClaims(
        issuer: String = "https://issuer.example",
        audience: String = "desktop-client",
        audienceIsJson: Boolean = false,
        exp: Long = now.epochSecond + 3_600,
        iat: Long = now.epochSecond,
        nbf: Long? = null,
        nonce: String = "nonce",
        extra: String = "",
    ): String {
        val aud = if (audienceIsJson) audience else "\"$audience\""
        val nbfClaim = nbf?.let { "\"nbf\":$it," }.orEmpty()
        return """{"iss":"$issuer","sub":"subject","aud":$aud,"exp":$exp,"iat":$iat,$nbfClaim$extra"nonce":"$nonce"}"""
    }
}

private fun jwksServer(currentKey: AtomicReference<Pair<String, KeyPair>>): HttpServer =
    HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
        createContext("/jwks") { exchange ->
            val (keyId, pair) = currentKey.get()
            val key = pair.public as RSAPublicKey
            exchange.respondJson(
                """{"keys":[{"kty":"RSA","kid":"$keyId","use":"sig","alg":"RS256","n":"${key.modulus.unsignedBase64Url()}","e":"${key.publicExponent.unsignedBase64Url()}"}]}""",
            )
        }
        start()
    }

private fun token(
    keyPair: KeyPair,
    keyId: String,
    claims: String,
): String {
    val header = """{"alg":"RS256","kid":"$keyId"}""".base64UrlText()
    val body = claims.base64UrlText()
    val input = "$header.$body"
    val signature =
        Signature.getInstance("SHA256withRSA").run {
            initSign(keyPair.private)
            update(input.toByteArray(StandardCharsets.US_ASCII))
            sign().base64UrlBytes()
        }
    return "$input.$signature"
}

private fun rsaKeyPair(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

private fun String.base64UrlText(): String = toByteArray(StandardCharsets.UTF_8).base64UrlBytes()

private fun ByteArray.base64UrlBytes(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

private fun java.math.BigInteger.unsignedBase64Url(): String = toByteArray().dropWhile { it == 0.toByte() }.toByteArray().base64UrlBytes()

private fun HttpExchange.respondJson(body: String) {
    val bytes = body.toByteArray(StandardCharsets.UTF_8)
    responseHeaders.set("Content-Type", "application/json")
    sendResponseHeaders(200, bytes.size.toLong())
    responseBody.use { it.write(bytes) }
}
