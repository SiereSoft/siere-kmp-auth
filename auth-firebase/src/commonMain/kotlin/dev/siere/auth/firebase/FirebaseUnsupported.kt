package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult

internal fun unsupportedFirebaseOperation(
    operation: String,
    target: String,
): AuthResult.Failure =
    AuthResult.Failure(
        AuthError.Unsupported(operation = operation, target = "auth-firebase/$target"),
    )
