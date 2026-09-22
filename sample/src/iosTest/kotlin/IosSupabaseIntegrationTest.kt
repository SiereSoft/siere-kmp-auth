import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.SiereAuth
import io.github.jan.supabase.annotations.SupabaseExperimental
import io.github.jan.supabase.auth.FlowType
import io.github.jan.supabase.auth.MemoryCodeVerifierCache
import io.github.jan.supabase.auth.MemorySessionManager
import io.github.jan.supabase.auth.UrlLauncher
import io.github.jan.supabase.auth.auth
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(SupabaseExperimental::class)
class IosSupabaseIntegrationTest {
    @Test
    fun nativeAdapterCoversTheSessionLifecycle() =
        runTest {
            var requestIndex = 0
            val engine =
                MockEngine { request ->
                    assertEquals("sb_publishable_ios_test", request.headers["apikey"])
                    when (requestIndex++) {
                        0 -> {
                            assertEquals("/auth/v1/token", request.url.encodedPath)
                            assertEquals("password", request.url.parameters["grant_type"])
                            json(SIGN_IN_RESPONSE)
                        }

                        1 -> {
                            assertEquals("/auth/v1/token", request.url.encodedPath)
                            assertEquals("refresh_token", request.url.parameters["grant_type"])
                            json(REFRESH_RESPONSE)
                        }

                        2 -> {
                            assertEquals("/auth/v1/recover", request.url.encodedPath)
                            assertEquals(
                                "dev.siere.auth.sample://auth-callback",
                                request.url.parameters["redirect_to"],
                            )
                            json("{}")
                        }

                        3 -> {
                            assertEquals("/auth/v1/logout", request.url.encodedPath)
                            assertEquals("local", request.url.parameters["scope"])
                            assertEquals("Bearer refreshed-access-token", request.headers[HttpHeaders.Authorization])
                            json("{}")
                        }

                        else -> error("Unexpected Supabase request: ${request.url}")
                    }
                }
            val client = testClient(engine)
            val auth = SiereAuth(iosSupabaseProvider(client))

            try {
                assertEquals("dev.siere.auth.sample", client.auth.config.scheme)
                assertEquals("auth-callback", client.auth.config.host)
                assertEquals(FlowType.PKCE, client.auth.config.flowType)

                assertEmailSignIn(auth)

                val refreshed =
                    assertIs<AuthResult.Success<AuthSession>>(
                        auth.currentSession(forceRefresh = true),
                    ).value
                assertEquals("refreshed-access-token", refreshed.accessToken)
                assertEquals("refreshed-refresh-token", refreshed.refreshToken)

                assertIs<AuthResult.Success<Unit>>(auth.sendPasswordReset("ios@example.com"))
                assertIs<AuthState.SignedIn>(auth.authState.value)

                assertIs<AuthResult.Success<Unit>>(auth.signOut())
                withContext(Dispatchers.Default) {
                    withTimeout(5_000) { auth.authState.first { it is AuthState.SignedOut } }
                }
                assertNull(client.auth.currentSessionOrNull())
                assertEquals(4, requestIndex)
            } finally {
                auth.close()
                client.close()
            }
        }

    @Test
    fun savedSupabaseSessionIsRestoredByANewIosAdapter() =
        runTest {
            val sessions = MemorySessionManager()
            var requests = 0
            val engine =
                MockEngine {
                    requests += 1
                    json(SIGN_IN_RESPONSE)
                }
            val firstClient = testClient(engine, sessions, autoLoad = false, autoSave = true)
            val firstAuth = SiereAuth(iosSupabaseProvider(firstClient))

            assertIs<AuthResult.Success<AuthUser>>(
                firstAuth.signInWithEmail("ios@example.com", "correct horse battery staple"),
            )
            firstAuth.close()
            firstClient.close()

            val restoredClient =
                testClient(
                    engine = MockEngine { error("Restoration must not call Supabase") },
                    sessions = sessions,
                    autoLoad = true,
                    autoSave = true,
                )
            restoredClient.auth.awaitInitialization()
            val restoredAuth = SiereAuth(iosSupabaseProvider(restoredClient))
            try {
                val state =
                    withContext(Dispatchers.Default) {
                        withTimeout(5_000) { restoredAuth.authState.first { it !is AuthState.Loading } }
                    }
                assertEquals("ios-test-user", assertIs<AuthState.SignedIn>(state).user.uid)
                val session = assertIs<AuthResult.Success<AuthSession>>(restoredAuth.currentSession()).value
                assertEquals("ios-access-token", session.accessToken)
                assertEquals(1, requests)
            } finally {
                restoredAuth.close()
                restoredClient.close()
            }
        }

    @Test
    fun callbackRouterForwardsOnlyTheConfiguredIosUrl() {
        var accepted: String? = null
        val forward: (platform.Foundation.NSURL) -> Unit = { accepted = it.absoluteString }

        assertFalse(routeIosSupabaseCallback("not a URL", forward))
        assertFalse(routeIosSupabaseCallback("other.scheme://auth-callback?code=no", forward))
        assertFalse(routeIosSupabaseCallback("dev.siere.auth.sample://other-host?code=no", forward))
        assertNull(accepted)

        val callback = "dev.siere.auth.sample://auth-callback?code=accepted"
        assertTrue(routeIosSupabaseCallback(callback, forward))
        assertEquals(callback, accepted)
    }

    @Test
    fun googlePkceCallbackCompletesThroughTheIosHost() =
        runTest {
            val launchedUrl = CompletableDeferred<String>()
            var exchanges = 0
            var exchangePath: String? = null
            var exchangeGrant: String? = null
            val client =
                createIosSupabaseClient(
                    supabaseUrl = "https://sample.supabase.co",
                    supabasePublishableKey = "sb_publishable_ios_test",
                    httpEngine =
                        MockEngine { request ->
                            exchanges += 1
                            exchangePath = request.url.encodedPath
                            exchangeGrant = request.url.parameters["grant_type"]
                            json(GOOGLE_SIGN_IN_RESPONSE)
                        },
                    testMode = true,
                    codeVerifierCache = MemoryCodeVerifierCache(),
                    urlLauncher = UrlLauncher { _, url -> launchedUrl.complete(url) },
                )
            val auth = SiereAuth(iosSupabaseProvider(client))
            val host = IosSupabaseHost(client, "sample.supabase.co")
            try {
                val signIn = async(Dispatchers.Default) { auth.signInWithGoogle() }
                val authorizationUrl =
                    withContext(Dispatchers.Default) {
                        withTimeout(5_000) { launchedUrl.await() }
                    }
                assertTrue("provider=google" in authorizationUrl)
                assertTrue("redirect_to=dev.siere.auth.sample" in authorizationUrl)

                assertTrue(host.handleOpenUrl("dev.siere.auth.sample://auth-callback?code=test-code"))

                val result =
                    withContext(Dispatchers.Default) {
                        withTimeout(5_000) { signIn.await() }
                    }
                assertTrue(result is AuthResult.Success, "OAuth result was $result")
                val user = result.value
                assertEquals("google-user", user.uid)
                assertTrue("google.com" in user.providerIds)
                assertEquals(1, exchanges)
                assertEquals("/auth/v1/token", exchangePath)
                assertEquals("pkce", exchangeGrant)
            } finally {
                auth.close()
                host.close()
            }
        }

    @Test
    fun googleCancellationReturnsCancelledWithoutATokenExchange() =
        runTest {
            val launchedUrl = CompletableDeferred<String>()
            var requests = 0
            val client =
                createIosSupabaseClient(
                    supabaseUrl = "https://sample.supabase.co",
                    supabasePublishableKey = "sb_publishable_ios_test",
                    httpEngine =
                        MockEngine {
                            requests += 1
                            error("Cancellation must not exchange a token")
                        },
                    testMode = true,
                    codeVerifierCache = MemoryCodeVerifierCache(),
                    urlLauncher = UrlLauncher { _, url -> launchedUrl.complete(url) },
                )
            val auth = SiereAuth(iosSupabaseProvider(client))
            val host = IosSupabaseHost(client, "sample.supabase.co")
            try {
                val signIn = async(Dispatchers.Default) { auth.signInWithGoogle() }
                withContext(Dispatchers.Default) {
                    withTimeout(5_000) { launchedUrl.await() }
                }

                assertTrue(
                    host.handleOpenUrl(
                        "dev.siere.auth.sample://auth-callback" +
                            "?error=access_denied&error_code=access_denied&error_description=cancelled",
                    ),
                )

                val result =
                    withContext(Dispatchers.Default) {
                        withTimeout(5_000) { signIn.await() }
                    }
                val failure = assertIs<AuthResult.Failure>(result)
                assertIs<AuthError.Cancelled>(failure.error)
                assertEquals("access_denied", failure.error.providerCode)
                assertEquals(0, requests)
            } finally {
                auth.close()
                host.close()
            }
        }

    private suspend fun signedInState(auth: SiereAuth): AuthState.SignedIn =
        withContext(Dispatchers.Default) {
            assertIs(withTimeout(5_000) { auth.authState.first { it is AuthState.SignedIn } })
        }

    private suspend fun assertEmailSignIn(auth: SiereAuth) {
        val user =
            assertIs<AuthResult.Success<AuthUser>>(
                auth.signInWithEmail("ios@example.com", "correct horse battery staple"),
            ).value
        assertEquals("ios-test-user", user.uid)
        assertEquals("ios@example.com", user.email)
        assertEquals("ios-test-user", signedInState(auth).user.uid)
    }

    private fun testClient(
        engine: MockEngine,
        sessions: MemorySessionManager? = null,
        autoLoad: Boolean = false,
        autoSave: Boolean = false,
    ) = createIosSupabaseClient(
        supabaseUrl = "https://sample.supabase.co",
        supabasePublishableKey = "sb_publishable_ios_test",
        httpEngine = engine,
        testMode = true,
        sessionManager = sessions,
        autoLoadFromStorage = autoLoad,
        autoSaveToStorage = autoSave,
    )

    private fun MockRequestHandleScope.json(
        content: String,
        status: HttpStatusCode = HttpStatusCode.OK,
    ) = respond(
        content = content,
        status = status,
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
    )

    private companion object {
        const val SIGN_IN_RESPONSE =
            """{
                "access_token":"ios-access-token",
                "refresh_token":"ios-refresh-token",
                "expires_in":3600,
                "token_type":"bearer",
                "user":{
                    "id":"ios-test-user",
                    "aud":"authenticated",
                    "email":"ios@example.com",
                    "email_confirmed_at":"2026-09-22T10:00:00Z",
                    "identities":[{
                        "id":"email-ios-test-user",
                        "identity_data":{},
                        "provider":"email",
                        "user_id":"ios-test-user"
                    }]
                }
            }"""

        const val REFRESH_RESPONSE =
            """{
                "access_token":"refreshed-access-token",
                "refresh_token":"refreshed-refresh-token",
                "expires_in":3600,
                "token_type":"bearer",
                "user":{
                    "id":"ios-test-user",
                    "aud":"authenticated",
                    "email":"ios@example.com",
                    "email_confirmed_at":"2026-09-22T10:00:00Z",
                    "identities":[{
                        "id":"email-ios-test-user",
                        "identity_data":{},
                        "provider":"email",
                        "user_id":"ios-test-user"
                    }]
                }
            }"""

        const val GOOGLE_SIGN_IN_RESPONSE =
            """{
                "access_token":"google-access-token",
                "refresh_token":"google-refresh-token",
                "expires_in":3600,
                "token_type":"bearer",
                "user":{
                    "id":"google-user",
                    "aud":"authenticated",
                    "email":"google@example.com",
                    "email_confirmed_at":"2026-09-22T10:00:00Z",
                    "identities":[{
                        "id":"google-identity",
                        "identity_data":{},
                        "provider":"google",
                        "user_id":"google-user"
                    }]
                }
            }"""
    }
}
