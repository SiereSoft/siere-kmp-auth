package dev.siere.auth.firebase

import dev.siere.auth.AuthUser

internal fun firebaseAuthUser(
    uid: String,
    displayName: String?,
    email: String?,
    isEmailVerified: Boolean,
    photoUrl: String?,
    phoneNumber: String?,
    isAnonymous: Boolean,
    providerIds: Iterable<String>,
): AuthUser =
    AuthUser(
        uid = uid,
        displayName = displayName,
        email = email,
        isEmailVerified = isEmailVerified,
        photoUrl = photoUrl,
        phoneNumber = phoneNumber,
        isAnonymous = isAnonymous,
        providerIds =
            buildList {
                addAll(providerIds.map(::canonicalFirebaseProviderId).filter(String::isNotBlank))
                if (isAnonymous) add("anonymous")
            }.distinct(),
    )

// Keep this vocabulary aligned with auth-supabase's module-private canonicalProviderId. Sharing an
// internal function across Gradle modules would require exposing implementation detail as public API.
internal fun canonicalFirebaseProviderId(providerId: String): String =
    when (providerId) {
        "google", "google.com" -> "google.com"
        "apple", "apple.com" -> "apple.com"
        "email", "password" -> "password"
        else -> providerId
    }
