package dev.siere.auth.sample

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthState
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DemoAuthProviderTest {
    @Test
    fun brokenConfiguredProviderFallsBackToDemoWithoutThrowing() =
        runTest {
            val options =
                listOf(
                    demoProviderOption(),
                    ProviderOption("Broken") { error("malformed consumer configuration") },
                )

            val created = createProviderSafely(options, requestedIndex = 1)

            assertEquals(0, created.activeIndex)
            assertEquals("Could not start Broken. Demo remains active.", created.errorMessage)
            assertTrue(
                created.provider
                    .signInAnonymously()
                    .getOrNull()
                    ?.isAnonymous == true,
            )
        }

    @Test
    fun emailFlowAndSessionAreDeterministic() =
        runTest {
            val provider = DemoAuthProvider()

            val signedIn = provider.signInWithEmail("person@example.test", "correct")

            assertEquals("person@example.test", signedIn.getOrNull()?.email)
            assertIs<AuthState.SignedIn>(provider.authState.value)
            assertEquals("demo-access-token", provider.currentSession().getOrNull()?.accessToken)
            assertEquals(
                "demo-access-token-refreshed",
                provider.currentSession(forceRefresh = true).getOrNull()?.accessToken,
            )
        }

    @Test
    fun failurePathsDoNotSignIn() =
        runTest {
            val provider = DemoAuthProvider()

            val empty = provider.signInWithEmail("", "")
            val rejected = provider.signInWithEmail("person@example.test", DemoAuthProvider.FAILURE_PASSWORD)

            assertIs<AuthError.InvalidCredentials>((empty as AuthResult.Failure).error)
            assertIs<AuthError.InvalidCredentials>((rejected as AuthResult.Failure).error)
            assertIs<AuthState.SignedOut>(provider.authState.value)
        }

    @Test
    fun phoneAndAnonymousLinkingCoverMultiStepUiFlows() =
        runTest {
            val provider = DemoAuthProvider()
            val phone = provider.startPhoneSignIn("+359875555555").getOrNull()!!

            assertIs<AuthError.InvalidVerificationCode>(
                (phone.confirm("000000") as AuthResult.Failure).error,
            )
            assertEquals("+359875555555", phone.confirm(DemoAuthProvider.DEMO_PHONE_CODE).getOrNull()?.phoneNumber)

            provider.signOut()
            val guest = assertNotNull(provider.signInAnonymously().getOrNull())
            assertTrue(guest.isAnonymous)
            assertEquals(listOf("anonymous"), guest.providerIds)
            val linked = provider.linkWithGoogle().getOrNull()!!
            assertTrue(!linked.isAnonymous)
            assertEquals(listOf("google.com"), linked.providerIds)

            provider.signOut()
            val phoneGuest = provider.signInAnonymously().getOrNull()!!
            val phoneLink =
                provider
                    .startPhoneLinking("+359875555556")
                    .getOrNull()!!
                    .confirm(DemoAuthProvider.DEMO_PHONE_CODE)
                    .getOrNull()!!
            assertEquals(phoneGuest.uid, phoneLink.uid)
            assertEquals("+359875555556", phoneLink.phoneNumber)
            assertEquals(listOf("phone"), phoneLink.providerIds)
        }
}
