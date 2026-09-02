package dev.siere.auth.firebase

import dev.gitlive.firebase.auth.PhoneAuthProvider
import dev.siere.auth.AuthResult

internal expect suspend fun requestIosPhoneVerificationId(
    provider: PhoneAuthProvider,
    phoneNumber: String,
): AuthResult<String>
