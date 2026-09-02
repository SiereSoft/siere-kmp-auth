package dev.siere.auth.firebase

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SingleUseAuthOperationTest {
    @Test
    fun automaticCompletionWinsOverLaterCodeConfirmation() =
        runTest {
            val gate = SingleUseAuthOperation<String>()
            var exchanges = 0

            val automatic =
                gate.complete {
                    exchanges++
                    AuthResult.Success("automatic")
                }
            val code =
                gate.complete {
                    exchanges++
                    AuthResult.Success("code")
                }

            assertEquals("automatic", (automatic as AuthResult.Success).value)
            assertEquals("automatic", (code as AuthResult.Success).value)
            assertEquals(1, exchanges)
        }

    @Test
    fun codeConfirmationWinsAConcurrentAutomaticCompletion() =
        runTest {
            val gate = SingleUseAuthOperation<String>()
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            var exchanges = 0
            val code =
                async {
                    gate.complete {
                        exchanges++
                        entered.complete(Unit)
                        release.await()
                        AuthResult.Success("code")
                    }
                }
            entered.await()
            val automatic =
                async {
                    gate.complete {
                        exchanges++
                        AuthResult.Success("automatic")
                    }
                }
            release.complete(Unit)

            assertEquals("code", (code.await() as AuthResult.Success).value)
            assertEquals("code", (automatic.await() as AuthResult.Success).value)
            assertEquals(1, exchanges)
        }

    @Test
    fun terminalCallbackFailureIsCached() =
        runTest {
            val gate = SingleUseAuthOperation<String>()
            gate.fail(AuthResult.Failure(AuthError.Network()))

            val result = gate.complete { AuthResult.Success("must not run") }

            assertIs<AuthError.Network>((result as AuthResult.Failure).error)
        }
}
