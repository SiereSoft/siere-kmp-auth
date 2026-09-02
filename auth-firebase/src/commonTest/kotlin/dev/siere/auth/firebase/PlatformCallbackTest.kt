package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PlatformCallbackTest {
    @Test
    fun completedCallbackReturnsItsResult() =
        runTest {
            val deferred = CompletableDeferred<AuthResult<String>>(AuthResult.Success("ready"))

            val result = awaitPlatformCallback(deferred)

            assertEquals("ready", (result as AuthResult.Success).value)
        }

    @Test
    fun missingCallbackBecomesTypedNetworkFailure() =
        runTest {
            val result =
                awaitPlatformCallback<String>(
                    deferred = CompletableDeferred(),
                    timeoutMillis = 100,
                )

            assertIs<AuthError.Network>((result as AuthResult.Failure).error)
        }

    @Test
    fun callerTimeoutIsNotConvertedIntoAProviderFailure() =
        runTest {
            assertFailsWith<TimeoutCancellationException> {
                withTimeout(1) {
                    awaitPlatformCallback<String>(CompletableDeferred(), timeoutMillis = 60_000)
                }
            }
        }

    @Test
    fun appleNonceAlphabetIsStableAndUniformlyIndexable() {
        assertEquals(64, APPLE_NONCE_ALPHABET.length)
        assertEquals(64, APPLE_NONCE_ALPHABET.toSet().size)
        assertTrue('W' in APPLE_NONCE_ALPHABET)
    }
}
