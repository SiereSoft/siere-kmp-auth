package dev.siere.auth.firebase

import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ExpectedUserGuardTest {
    @Test
    fun rejectsAccountSwitchWhileLinkIsSuspended() =
        runTest {
            var currentUid: String? = "user-a"
            assertFailsWith<FirebaseAuthStateChangedException> {
                withExpectedUser("user-a", { currentUid }) {
                    yield()
                    currentUid = "user-b"
                    "linked-user-a"
                }
            }
        }

    @Test
    fun returnsResultWhenAccountRemainsCurrent() =
        runTest {
            val result = withExpectedUser("user-a", { "user-a" }) { "linked-user-a" }

            assertEquals("linked-user-a", result)
        }
}
