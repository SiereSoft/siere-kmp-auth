import dev.siere.auth.oidc.OidcAuthorizationRequest
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Runnable
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.test.runTest
import platform.AuthenticationServices.ASWebAuthenticationPresentationContextProvidingProtocol
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IosOidcAuthorizationHandlerTest {
    @Test
    fun returnsTheCallbackFromTheNativeSession() =
        runTest {
            val factory = FakeIosWebAuthenticationSessionFactory()
            val handler =
                IosOidcAuthorizationHandler(
                    presentationAnchor = { null },
                    sessionFactory = factory,
                    mainDispatcher = Dispatchers.Unconfined,
                )
            val request = request()

            val result = async(start = CoroutineStart.UNDISPATCHED) { handler.authorize(request) }
            factory.complete(
                IosWebAuthenticationResult.Callback(
                    "dev.siere.auth.sample://oidc/callback?code=test-code&state=test-state",
                ),
            )

            assertEquals(
                "dev.siere.auth.sample://oidc/callback?code=test-code&state=test-state",
                result.await(),
            )
            assertTrue(factory.session.started)
        }

    @Test
    fun convertsTheNativeCancelButtonIntoAnOidcAccessDeniedCallback() =
        runTest {
            val factory = FakeIosWebAuthenticationSessionFactory()
            val handler =
                IosOidcAuthorizationHandler(
                    presentationAnchor = { null },
                    sessionFactory = factory,
                    mainDispatcher = Dispatchers.Unconfined,
                )

            val result = async(start = CoroutineStart.UNDISPATCHED) { handler.authorize(request()) }
            factory.complete(IosWebAuthenticationResult.Cancelled)

            assertEquals(
                "dev.siere.auth.sample://oidc/callback" +
                    "?error=access_denied&error_description=cancelled&state=test-state",
                result.await(),
            )
        }

    @Test
    fun cancellingTheCoroutineCancelsTheNativeSession() =
        runTest {
            val factory = FakeIosWebAuthenticationSessionFactory()
            val dispatcher = RecordingDispatcher()
            val handler =
                IosOidcAuthorizationHandler(
                    presentationAnchor = { null },
                    sessionFactory = factory,
                    mainDispatcher = dispatcher,
                )

            val authorization = async(start = CoroutineStart.UNDISPATCHED) { handler.authorize(request()) }
            dispatcher.dispatchCount = 0
            authorization.cancelAndJoin()

            assertTrue(factory.session.cancelled)
            assertTrue(dispatcher.dispatchCount > 0)
        }

    private fun request() =
        OidcAuthorizationRequest(
            authorizationUrl =
                "https://identity.example/authorize" +
                    "?client_id=ios-app&state=test-state&code_challenge=test-challenge",
            redirectUri = "dev.siere.auth.sample://oidc/callback",
        )
}

private class RecordingDispatcher : kotlinx.coroutines.CoroutineDispatcher() {
    var dispatchCount = 0

    override fun dispatch(
        context: CoroutineContext,
        block: Runnable,
    ) {
        dispatchCount += 1
        block.run()
    }
}

private class FakeIosWebAuthenticationSessionFactory : IosWebAuthenticationSessionFactory {
    val session = FakeIosWebAuthenticationSession()
    private lateinit var completion: (IosWebAuthenticationResult) -> Unit

    override fun create(
        request: OidcAuthorizationRequest,
        presentationContext: ASWebAuthenticationPresentationContextProvidingProtocol,
        completion: (IosWebAuthenticationResult) -> Unit,
    ): IosWebAuthenticationSession {
        this.completion = completion
        return session
    }

    fun complete(result: IosWebAuthenticationResult) {
        completion(result)
    }
}

private class FakeIosWebAuthenticationSession : IosWebAuthenticationSession {
    var started = false
    var cancelled = false

    override fun start(): Boolean {
        started = true
        return true
    }

    override fun cancel() {
        cancelled = true
    }
}
