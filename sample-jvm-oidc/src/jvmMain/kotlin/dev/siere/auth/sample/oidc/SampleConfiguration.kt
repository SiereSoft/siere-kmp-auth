package dev.siere.auth.sample.oidc

import dev.siere.auth.oidc.OidcConfiguration
import java.net.URI

internal data class SampleConfiguration(
    val clientId: String,
    val discoveryUrl: String,
    val providerId: String,
    val allowInsecureLoopback: Boolean,
) {
    fun toOidcConfiguration(): OidcConfiguration =
        OidcConfiguration(
            clientId = clientId,
            discoveryUrl = discoveryUrl,
            scopes = setOf("profile", "email"),
            providerId = providerId,
            allowInsecureHttpForTesting = allowInsecureLoopback,
        )

    companion object {
        fun fromEnvironment(environment: Map<String, String> = System.getenv()): SampleConfiguration {
            val discoveryUrl = environment.nonBlank("SIERE_OIDC_DISCOVERY_URL") ?: DEFAULT_DISCOVERY_URL
            return SampleConfiguration(
                clientId = environment.nonBlank("SIERE_OIDC_CLIENT_ID") ?: DEFAULT_CLIENT_ID,
                discoveryUrl = discoveryUrl,
                providerId = environment.nonBlank("SIERE_OIDC_PROVIDER_ID") ?: DEFAULT_PROVIDER_ID,
                allowInsecureLoopback = discoveryUrl.isHttpLoopback(),
            )
        }
    }
}

private fun Map<String, String>.nonBlank(name: String): String? = get(name)?.trim()?.takeIf(String::isNotEmpty)

private fun String.isHttpLoopback(): Boolean =
    runCatching {
        val uri = URI(this)
        uri.scheme.equals("http", ignoreCase = true) &&
            (uri.host == "127.0.0.1" || uri.host == "::1" || uri.host == "[::1]") &&
            uri.userInfo == null &&
            uri.fragment == null
    }.getOrDefault(false)

private const val DEFAULT_CLIENT_ID = "siere-jvm-oidc"
private const val DEFAULT_DISCOVERY_URL =
    "http://127.0.0.1:8080/realms/siere/.well-known/openid-configuration"
private const val DEFAULT_PROVIDER_ID = "keycloak"
