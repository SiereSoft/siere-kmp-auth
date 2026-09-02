package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.withTimeoutOrNull

internal const val PLATFORM_CALLBACK_TIMEOUT_MILLIS: Long = 120_000L
internal const val ANDROID_PHONE_CALLBACK_TIMEOUT_MILLIS: Long = 75_000L
internal const val APPLE_NONCE_ALPHABET: String =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

/** Bounds platform-owned callbacks while preserving cancellation from the caller. */
internal suspend fun <T> awaitPlatformCallback(
    deferred: Deferred<AuthResult<T>>,
    timeoutMillis: Long = PLATFORM_CALLBACK_TIMEOUT_MILLIS,
): AuthResult<T> =
    withTimeoutOrNull(timeoutMillis) { deferred.await() }
        ?: run {
            AuthResult.Failure(
                AuthError.Network("Timed out waiting for the platform authentication callback"),
            )
        }
