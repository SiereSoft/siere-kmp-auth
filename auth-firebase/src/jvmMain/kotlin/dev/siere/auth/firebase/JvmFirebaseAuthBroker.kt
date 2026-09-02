package dev.siere.auth.firebase

/** Whether a hosted JVM flow will create a session or link the current Firebase user. */
public enum class JvmAuthOperation {
    SIGN_IN,
    LINK,
}

/** Apple assertion returned by consumer-owned trusted infrastructure after hosted authorization. */
public class JvmAppleCredential(
    idToken: String,
    rawNonce: String,
) {
    internal val idToken: String = idToken
    internal val rawNonce: String = rawNonce

    init {
        require(idToken.isNotBlank()) { "Apple ID token must not be blank" }
        require(rawNonce.isNotBlank()) { "Apple raw nonce must not be blank" }
    }

    override fun toString(): String = "JvmAppleCredential(idToken=<redacted>, rawNonce=<redacted>)"
}

/** Opaque, short-lived broker handle for an in-progress phone verification. */
public class JvmPhoneChallenge(
    public val handle: String,
) {
    init {
        require(handle.isNotBlank()) { "Phone challenge handle must not be blank" }
    }

    override fun toString(): String = "JvmPhoneChallenge(handle=<redacted>)"
}

/** Firebase phone assertion returned only after the broker has redeemed a single-use challenge. */
public class JvmPhoneCredential(
    verificationId: String,
    smsCode: String,
) {
    internal val verificationId: String = verificationId
    internal val smsCode: String = smsCode

    init {
        require(verificationId.isNotBlank()) { "Firebase verification ID must not be blank" }
        require(smsCode.isNotBlank()) { "SMS code must not be blank" }
    }

    override fun toString(): String = "JvmPhoneCredential(verificationId=<redacted>, smsCode=<redacted>)"
}

/**
 * Consumer-supplied hosted authorization boundary for JVM Apple and phone flows.
 *
 * Implementations own their HTTPS redirect endpoint, Apple client-secret signing, Firebase Web
 * reCAPTCHA/app verification, expiry, replay protection, and rate limiting. Browser callbacks must
 * carry only an opaque single-use code; Apple tokens, Firebase verification IDs, SMS codes, `.p8`
 * keys, and service credentials must never be placed in callback URLs.
 */
public interface JvmFirebaseAuthBroker : AutoCloseable {
    /** Runs hosted Apple authorization and redeems its opaque result over trusted transport. */
    public suspend fun authorizeApple(operation: JvmAuthOperation): JvmAppleCredential

    /** Starts hosted Firebase Web phone verification and returns an opaque broker challenge. */
    public suspend fun startPhoneVerification(
        phoneNumber: String,
        operation: JvmAuthOperation,
    ): JvmPhoneChallenge

    /** Redeems [challenge] and [smsCode] once for a Firebase phone assertion. */
    public suspend fun completePhoneVerification(
        challenge: JvmPhoneChallenge,
        smsCode: String,
    ): JvmPhoneCredential

    /** Releases broker-owned callbacks and browser work. Must be idempotent. */
    override fun close(): Unit = Unit
}
