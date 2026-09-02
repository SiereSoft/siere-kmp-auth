package dev.siere.auth

/**
 * A signed-in user, normalized across providers.
 *
 * Instances are immutable snapshots; observe [AuthProvider.authState] for changes.
 *
 * @property uid The provider's unique, stable identifier for this user.
 * @property displayName Human-readable name, when the provider shares one.
 * @property email Email address, when available; see [isEmailVerified] for its status.
 * @property isEmailVerified Whether the provider has verified [email].
 * @property photoUrl Avatar URL, when the provider shares one.
 * @property phoneNumber E.164 phone number, when the user signed in with or linked a phone.
 * @property isAnonymous Whether this is a guest session that can later be upgraded via linking.
 * @property providerIds Identifiers of the sign-in methods attached to this user
 * (for example `google.com`, `apple.com`, `phone`, `password`).
 */
public data class AuthUser(
    val uid: String,
    val displayName: String? = null,
    val email: String? = null,
    val isEmailVerified: Boolean = false,
    val photoUrl: String? = null,
    val phoneNumber: String? = null,
    val isAnonymous: Boolean = false,
    val providerIds: List<String> = emptyList(),
)
