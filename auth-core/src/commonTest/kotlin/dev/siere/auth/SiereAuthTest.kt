package dev.siere.auth

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SiereAuthTest {
    @Test
    fun signInMovesStateToSignedIn() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())

            val result = auth.signInWithGoogle()

            assertTrue(result.isSuccess)
            assertIs<AuthState.SignedIn>(auth.authState.value)
            assertEquals("fake-uid", auth.currentUser?.uid)
        }

    @Test
    fun failedSignInLeavesStateSignedOut() =
        runTest {
            val provider = FakeAuthProvider()
            provider.failNextWith(AuthError.PopupBlocked())
            val auth = SiereAuth(provider)

            val result = auth.signInWithGoogle()

            assertIs<AuthResult.Failure>(result)
            assertIs<AuthError.PopupBlocked>(result.error)
            assertIs<AuthState.SignedOut>(auth.authState.value)
            assertNull(auth.currentUser)
        }

    @Test
    fun signOutMovesStateToSignedOut() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())
            auth.signInWithGoogle()

            val result = auth.signOut()

            assertTrue(result.isSuccess)
            assertIs<AuthState.SignedOut>(auth.authState.value)
        }

    @Test
    fun anonymousSignInProducesGuestUser() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())

            auth.signInAnonymously()

            assertTrue(auth.currentUser?.isAnonymous == true)
        }

    @Test
    fun phoneSignInConfirmsWithValidCode() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())

            val session = auth.startPhoneSignIn("+359875555555").getOrNull()!!
            assertEquals("+359875555555", session.phoneNumber)

            val confirmed = session.confirm(FakeAuthProvider.VALID_CODE)

            assertEquals("+359875555555", confirmed.getOrNull()?.phoneNumber)
            assertIs<AuthState.SignedIn>(auth.authState.value)
        }

    @Test
    fun currentSessionReturnsFreshTokenWhenSignedIn() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())
            auth.signInWithGoogle()

            val session = auth.currentSession().getOrNull()!!
            assertEquals("fake-token", session.accessToken)
            assertEquals("fake-uid", session.user.uid)

            val refreshed = auth.currentSession(forceRefresh = true).getOrNull()!!
            assertEquals("fake-token-refreshed", refreshed.accessToken)
        }

    @Test
    fun currentSessionFailsWhenSignedOut() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())

            val result = auth.currentSession()

            assertIs<AuthResult.Failure>(result)
            assertIs<AuthError.NotSignedIn>(result.error)
        }

    @Test
    fun phoneSignInRejectsWrongCode() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())

            val session = auth.startPhoneSignIn("+359875555555").getOrNull()!!
            val confirmed = session.confirm("000000")

            assertIs<AuthResult.Failure>(confirmed)
            assertIs<AuthError.InvalidVerificationCode>(confirmed.error)
            assertIs<AuthState.SignedOut>(auth.authState.value)
        }

    @Test
    fun phoneLinkingPreservesTheCurrentUser() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())
            val guest = auth.signInAnonymously().getOrNull()!!

            val session = auth.startPhoneLinking("+359875555555").getOrNull()!!
            val linked = session.confirm(FakeAuthProvider.VALID_CODE).getOrNull()!!

            assertEquals(guest.uid, linked.uid)
            assertEquals("+359875555555", linked.phoneNumber)
            assertEquals(listOf("phone"), linked.providerIds)
            assertTrue(!linked.isAnonymous)
        }

    @Test
    fun phoneLinkingRequiresAnExistingUser() =
        runTest {
            val auth = SiereAuth(FakeAuthProvider())

            val result = auth.startPhoneLinking("+359875555555")

            assertIs<AuthError.NotSignedIn>((result as AuthResult.Failure).error)
        }

    @Test
    fun phoneLinkingRejectsAnAccountSwitchBeforeConfirmation() =
        runTest {
            val provider = FakeAuthProvider()
            val auth = SiereAuth(provider)
            auth.signInAnonymously()
            val session = auth.startPhoneLinking("+359875555555").getOrNull()!!
            provider.replaceSignedInUser(AuthUser(uid = "different-user"))

            val result = session.confirm(FakeAuthProvider.VALID_CODE)

            assertIs<AuthError.AuthStateChanged>((result as AuthResult.Failure).error)
            assertEquals("different-user", (auth.authState.value as AuthState.SignedIn).user.uid)
        }

    @Test
    fun closeReleasesTheConfiguredProvider() {
        val provider = FakeAuthProvider()
        val auth = SiereAuth(provider)

        auth.close()

        assertTrue(provider.isClosed)
    }
}
