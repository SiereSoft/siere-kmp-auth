package dev.siere.auth.supabase

import io.github.jan.supabase.annotations.SupabaseExperimental
import io.github.jan.supabase.auth.event.AuthEvent
import io.github.jan.supabase.auth.status.SessionSource
import io.github.jan.supabase.auth.status.SessionStatus
import io.github.jan.supabase.auth.user.Identity
import io.github.jan.supabase.auth.user.UserInfo
import io.github.jan.supabase.auth.user.UserSession
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.time.Instant

@OptIn(ExperimentalCoroutinesApi::class, SupabaseExperimental::class)
class SupabaseAuthTransitionTest {
    @Test
    fun oauthCompletionSkipsThePreExistingSignedInUser() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(authenticatedSession("old-user"))

            val result =
                async(start = CoroutineStart.UNDISPATCHED) {
                    awaitNextOAuthResult(
                        statuses,
                        MutableSharedFlow(),
                        timeoutMillis = 1_000,
                    )
                }
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
                awaitNextOAuthResult(statuses, MutableSharedFlow(), timeoutMillis = 1)
            }
        }

    @Test
    fun callerTimeoutIsNotReplacedByTheOAuthDeadline() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(SessionStatus.NotAuthenticated())

            assertFailsWith<TimeoutCancellationException> {
                withTimeout(1) {
                    awaitNextOAuthResult(statuses, MutableSharedFlow(), timeoutMillis = 60_000)
                }
            }
        }

    @Test
    fun oauthCompletionRequiresTheInitiatedProvider() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(SessionStatus.NotAuthenticated())
            val result =
                async(start = CoroutineStart.UNDISPATCHED) {
                    awaitNextOAuthResult(
                        statuses = statuses,
                        events = MutableSharedFlow(),
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

            val result =
                async {
                    awaitNextOAuthResult(
                        statuses,
                        MutableSharedFlow(),
                        timeoutMillis = 1_000,
                    )
                }
            runCurrent()
            statuses.value =
                authenticatedSession(
                    "same-user",
                    accessToken = "oauth-session-token",
                    source = SessionSource.External,
                )

            assertEquals("same-user", result.await().uid)
        }

    @Test
    fun oauthCancellationCompletesImmediately() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(SessionStatus.NotAuthenticated())
            val events = MutableSharedFlow<AuthEvent>(extraBufferCapacity = 1)
            val result =
                async {
                    runCatching {
                        awaitNextOAuthResult(
                            statuses = statuses,
                            events = events,
                            timeoutMillis = 60_000,
                            expectedProviderId = "google.com",
                        )
                    }
                }
            runCurrent()

            events.emit(AuthEvent.OtpError("access_denied", "The user cancelled"))

            val failure = assertIs<OAuthCallbackException>(result.await().exceptionOrNull())
            assertEquals("access_denied", failure.providerCode)
        }

    @Test
    fun oauthCompletionIgnoresAReplayedErrorFromAnEarlierAttempt() =
        runTest {
            val statuses = MutableStateFlow<SessionStatus>(SessionStatus.NotAuthenticated())
            val events = MutableSharedFlow<AuthEvent>(replay = 1)
            events.emit(AuthEvent.OtpError("stale_error", "Earlier attempt"))
            val result =
                async(start = CoroutineStart.UNDISPATCHED) {
                    runCatching {
                        awaitNextOAuthResult(
                            statuses = statuses,
                            events = events,
                            timeoutMillis = 60_000,
                            expectedProviderId = "google.com",
                        )
                    }
                }
            assertFalse(result.isCompleted)

            events.emit(AuthEvent.OtpError("access_denied", "Current attempt"))

            val failure = assertIs<OAuthCallbackException>(result.await().exceptionOrNull())
            assertEquals("access_denied", failure.providerCode)
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
