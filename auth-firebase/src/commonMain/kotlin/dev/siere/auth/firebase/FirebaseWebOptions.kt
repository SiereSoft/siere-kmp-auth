package dev.siere.auth.firebase

/**
 * Firebase configuration for the browser targets (`js` and `wasmJs`), copied from
 * Firebase console -> Project settings -> Your apps -> Web app.
 *
 * The native targets don't use this: Android reads `google-services.json`, iOS reads
 * `GoogleService-Info.plist`, and both are expected to have initialized Firebase before
 * a provider is constructed.
 *
 * @property appVerificationDisabledForTesting Skips the phone sign-in reCAPTCHA for numbers
 * registered as test numbers in the Firebase console. This is an explicit test-only escape hatch:
 * never derive it from remote/browser configuration or enable it in production builds.
 */
public data class FirebaseWebOptions(
    val apiKey: String,
    val authDomain: String,
    val projectId: String,
    val applicationId: String,
    val appVerificationDisabledForTesting: Boolean = false,
)
