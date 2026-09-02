@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package dev.siere.auth.firebase

import dev.gitlive.firebase.auth.PhoneAuthProvider
import dev.gitlive.firebase.auth.ios
import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

internal actual suspend fun requestIosPhoneVerificationId(
    provider: PhoneAuthProvider,
    phoneNumber: String,
): AuthResult<String> =
    suspendCancellableCoroutine { continuation ->
        provider.ios.verifyPhoneNumber(phoneNumber, null) { identifier, error ->
            if (!continuation.isActive) return@verifyPhoneNumber
            continuation.resume(
                when {
                    error != null -> AuthResult.Failure(firebaseAuthError(error.localizedDescription))
                    identifier == null ->
                        AuthResult.Failure(
                            AuthError.Unknown("Firebase returned no phone verification ID"),
                        )
                    else -> AuthResult.Success(identifier)
                },
            )
        }
    }
