package dev.siere.auth.supabase

import io.github.jan.supabase.auth.status.SessionSource
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.Identity
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.auth.user.UserSession
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.time.Instant

@OptIn(ExperimentalCoroutinesApi::class)
class SupabaseAuthTransitionTest {
    @Test
    fun oauthCompletionSkipsThePreExistingSignedInUser() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(authenticatedSession("old-user"))

            val result = async { awaitNextAuthenticatedUser(statuses, timeoutMillis = 1_000) }
            runCurrent()

            assertFalse(result.isCompleted)
            statuses.value =
                authenticatedSession(
                    "old-user",
                    accessToken = "refreshed-old-token",
                    source = SessionSource.Refresh(testSession("old-user")),
                )
            runCurrent()
            assertFalse(result.isCompleted)
            statuses.value = SessionStatus.NotAuthenticated()
            statuses.value = authenticatedSession("new-user")

            assertEquals("new-user", result.await().uid)
        }

    @Test
    fun oauthCompletionHasABoundedTimeout() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(SessionStatus.NotAuthenticated())

            assertFailsWith<AuthCompletionTimeoutException> {
                awaitNextAuthenticatedUser(statuses, timeoutMillis = 1)
            }
        }

    @Test
    fun callerTimeoutIsNotReplacedByTheOAuthDeadline() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(SessionStatus.NotAuthenticated())

            assertFailsWith<TimeoutCancellationException> {
                withTimeout(1) {
                    awaitNextAuthenticatedUser(statuses, timeoutMillis = 60_000)
                }
            }
        }

    @Test
    fun oauthCompletionRequiresTheInitiatedProvider() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(SessionStatus.NotAuthenticated())
            val result =
                async {
                    awaitNextAuthenticatedUser(
                        statuses,
                        timeoutMillis = 1_000,
                        expectedProviderId = "google.com",
                    )
                }
            runCurrent()

            statuses.value = authenticatedSession("apple-user", provider = "apple")
            runCurrent()
            assertFalse(result.isCompleted)
            statuses.value = authenticatedSession("google-user", provider = "google")

            assertEquals("google-user", result.await().uid)
        }

    @Test
    fun sameAccountExternalCompletionIsAcceptedAsNewSession() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(authenticatedSession("same-user"))

            val result = async { awaitNextAuthenticatedUser(statuses, timeoutMillis = 1_000) }
            runCurrent()
            statuses.value =
                authenticatedSession(
                    "same-user",
                    accessToken = "oauth-session-token",
                    source = SessionSource.External,
                )

            assertEquals("same-user", result.await().uid)
        }

    private fun authenticatedSession(
        uid: String,
        accessToken: String = "access-$uid",
        source: SessionSource = SessionSource.External,
        provider: String? = null,
    ): SessionStatus.Authenticated =
        SessionStatus.Authenticated(
            session = testSession(uid, accessToken, provider),
            source = source,
        )

    private fun testSession(
        uid: String,
        accessToken: String = "access-$uid",
        provider: String? = null,
    ): UserSession =
        UserSession(
            accessToken = accessToken,
            refreshToken = "refresh-$uid",
            expiresIn = 3_600,
            tokenType = "bearer",
            user =
                UserInfo(
                    id = uid,
                    aud = "authenticated",
                    identities =
                        provider?.let {
                            listOf(
                                Identity(
                                    id = "$provider-$uid",
                                    identityData = buildJsonObject {},
                                    provider = provider,
                                    userId = uid,
                                ),
                            )
                        },
                ),
            expiresAt = Instant.parse("2099-12-31T23:59:59Z"),
        )
}
