package dev.siere.auth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthResultTest {
    private val error = AuthError.Unknown(message = "boom", providerCode = "auth/boom")

    @Test
    fun mapTransformsSuccessAndPassesFailureThrough() {
        assertEquals(
            AuthResult.Success(4),
            AuthResult.Success(2).map { it * 2 },
        )
        assertEquals(
            AuthResult.Failure(error),
            (AuthResult.Failure(error) as AuthResult<Int>).map { it * 2 },
        )
    }

    @Test
    fun accessorsReturnTheMatchingSide() {
        assertEquals(2, AuthResult.Success(2).getOrNull())
        assertNull(AuthResult.Success(2).errorOrNull())
        assertNull(AuthResult.Failure(error).getOrNull())
        assertEquals(error, AuthResult.Failure(error).errorOrNull())
        assertTrue(AuthResult.Success(Unit).isSuccess)
    }

    @Test
    fun callbacksFireOnTheMatchingSideOnly() {
        var seen: Any? = null
        AuthResult.Success(1).onSuccess { seen = it }.onFailure { seen = it }
        assertEquals(1, seen)

        AuthResult.Failure(error).onSuccess { seen = it }.onFailure { seen = it }
        assertIs<AuthError.Unknown>(seen)
    }
}
