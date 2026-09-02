package dev.siere.auth.sample

/** Rejects Supabase keys that are explicitly marked as server-side secrets. */
internal fun requirePublishableSupabaseKey(key: String): String {
    val normalized = key.trim()
    require(normalized.isNotEmpty()) { "The Supabase publishable key is blank" }
    require(!normalized.startsWith("sb_secret_", ignoreCase = true)) {
        "Supabase secret keys must never be used in a client application"
    }
    require(!normalized.contains("service_role", ignoreCase = true)) {
        "Supabase service-role keys must never be used in a client application"
    }
    require(!hasPrivilegedSupabaseJwtRole(normalized)) {
        "Supabase service-role keys must never be used in a client application"
    }
    return normalized
}

internal fun publishableSupabaseKeyOrNull(key: String?): String? =
    key?.let { candidate -> runCatching { requirePublishableSupabaseKey(candidate) }.getOrNull() }

private fun hasPrivilegedSupabaseJwtRole(key: String): Boolean {
    val payload = key.split('.').takeIf { it.size == 3 }?.get(1) ?: return false
    val decoded = decodeBase64Url(payload) ?: return false
    return PRIVILEGED_ROLE_PATTERN.containsMatchIn(decoded)
}

private fun decodeBase64Url(value: String): String? {
    val bytes = mutableListOf<Byte>()
    var buffer = 0
    var bufferedBits = 0

    for (character in value.trimEnd('=')) {
        val sixBits = BASE64_URL_ALPHABET.indexOf(character)
        if (sixBits < 0) return null
        buffer = (buffer shl 6) or sixBits
        bufferedBits += 6
        if (bufferedBits >= 8) {
            bufferedBits -= 8
            bytes += ((buffer shr bufferedBits) and 0xff).toByte()
            buffer = if (bufferedBits == 0) 0 else buffer and ((1 shl bufferedBits) - 1)
        }
    }

    return runCatching { bytes.toByteArray().decodeToString() }.getOrNull()
}

private const val BASE64_URL_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

private val PRIVILEGED_ROLE_PATTERN =
    Regex("\"role\"\\s*:\\s*\"(?:service[_-]?role|supabase_admin)\"", RegexOption.IGNORE_CASE)
