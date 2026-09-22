package dev.siere.auth.sample

import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import dev.siere.auth.AuthUser
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class AuthenticatedBackendCallTest {
    @Test
    fun retriesOneUnauthorizedResponseWithAForcedRefresh() =
        runTest {
            val refreshRequests = mutableListOf<Boolean>()
            val tokens = mutableListOf<String>()

            val result =
                authenticatedBackendCall(
                    currentSession = { forceRefresh ->
                        refreshRequests += forceRefresh
                        AuthResult.Success(session(if (forceRefresh) "fresh-token" else "cached-token"))
                    },
                    request = { token ->
                        tokens += token
                        if (token == "cached-token") {
                            SampleBackendResponse(401, "unused")
                        } else {
                            SampleBackendResponse(200, "Protected call succeeded")
                        }
                    },
                )

            assertEquals(listOf(false, true), refreshRequests)
            assertEquals(listOf("cached-token", "fresh-token"), tokens)
            assertEquals(
                "Protected call succeeded",
                assertIs<AuthenticatedCallResult.Success>(result).message,
            )
        }

    @Test
    fun forcedRefreshBeforeTheCallDoesNotLoopOnUnauthorized() =
        runTest {
            var sessionRequests = 0
            var backendRequests = 0

            val result =
                authenticatedBackendCall(
                    forceRefreshBeforeCall = true,
                    currentSession = { forceRefresh ->
                        assertEquals(true, forceRefresh)
                        sessionRequests += 1
                        AuthResult.Success(session("fresh-token"))
                    },
                    request = {
                        backendRequests += 1
                        SampleBackendResponse(401, "unused")
                    },
                )

            assertEquals(1, sessionRequests)
            assertEquals(1, backendRequests)
            assertEquals(401, assertIs<AuthenticatedCallResult.HttpFailure>(result).statusCode)
        }

    private fun session(accessToken: String) =
        AuthSession(
            user = AuthUser(uid = "keycloak|demo", providerIds = listOf("keycloak")),
            accessToken = accessToken,
        )
}
