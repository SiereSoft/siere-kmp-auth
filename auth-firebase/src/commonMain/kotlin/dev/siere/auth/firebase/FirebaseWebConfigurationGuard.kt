package dev.siere.auth.firebase

/**
 * Firebase's browser default app is process-global. Reusing it for another project would silently
 * authenticate against the wrong backend, so a second provider must use the same app identity.
 */
internal fun requireCompatibleWebConfiguration(
    initialized: FirebaseWebOptions,
    requested: FirebaseWebOptions,
) {
    require(initialized.sameFirebaseAppAs(requested)) {
        "A Firebase web app is already initialized with different configuration"
    }
}

private fun FirebaseWebOptions.sameFirebaseAppAs(other: FirebaseWebOptions): Boolean =
    apiKey == other.apiKey &&
        authDomain == other.authDomain &&
        projectId == other.projectId &&
        applicationId == other.applicationId
