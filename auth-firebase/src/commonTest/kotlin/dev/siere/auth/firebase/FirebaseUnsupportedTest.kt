package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class FirebaseUnsupportedTest {
    @Test
    fun unsupportedCapabilitiesAreExplicitAndTargeted() {
        val result = unsupportedFirebaseOperation("Phone sign-in", "iOS")
        val error = assertIs<AuthError.Unsupported>(result.error)

        assertEquals("Phone sign-in", error.operation)
        assertEquals("auth-firebase/iOS", error.target)
    }
}
