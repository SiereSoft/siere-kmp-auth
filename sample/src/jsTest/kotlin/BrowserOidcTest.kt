import dev.siere.auth.AuthError
import dev.siere.auth.oidc.OidcAuthorizationRequest
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlin.js.json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BrowserOidcTest {
    @Test
    fun acceptsOnlyTheExpectedOriginSourcePayloadAndCallback() {
        val source = Any()
        val callback = "$JS_OIDC_REDIRECT_URI?code=code&state=state"
        val valid = BrowserOidcMessage(JS_SAMPLE_ORIGIN, source, "siere-oidc-callback", 1, callback)

        assertEquals(callback, validatedCallbackUrl(valid, source))
        assertNull(validatedCallbackUrl(valid.copy(origin = "http://localhost:8081"), source))
        assertNull(validatedCallbackUrl(valid.copy(source = Any()), source))
        assertNull(validatedCallbackUrl(valid.copy(source = null), source))
        assertNull(validatedCallbackUrl(valid.copy(type = "other"), source))
        assertNull(validatedCallbackUrl(valid.copy(version = 2), source))
        assertNull(validatedCallbackUrl(valid.copy(callbackUrl = null), source))
        assertNull(validatedCallbackUrl(valid.copy(callbackUrl = "https://127.0.0.1:8081/oidc-callback.html"), source))
        assertNull(validatedCallbackUrl(valid.copy(callbackUrl = "http://localhost:8081/oidc-callback.html"), source))
        assertNull(validatedCallbackUrl(valid.copy(callbackUrl = "http://127.0.0.1:8082/oidc-callback.html"), source))
        assertNull(validatedCallbackUrl(valid.copy(callbackUrl = "$JS_OIDC_REDIRECT_URI/other?code=x"), source))
        assertNull(validatedCallbackUrl(valid.copy(callbackUrl = "$callback#fragment"), source))
    }

    @Test
    fun domPayloadParsingRejectsWrongTypesAndFractionalVersions() {
        val source = Any()
        val wrongTypes =
            browserOidcMessage(
                JS_SAMPLE_ORIGIN,
                source,
                json("type" to 7, "version" to "1", "callbackUrl" to 42),
            )
        val fractional =
            browserOidcMessage(
                JS_SAMPLE_ORIGIN,
                source,
                json(
                    "type" to "siere-oidc-callback",
                    "version" to 1.5,
                    "callbackUrl" to "$JS_OIDC_REDIRECT_URI?code=code&state=state",
                ),
            )

        assertNull(wrongTypes.type)
        assertNull(wrongTypes.version)
        assertNull(wrongTypes.callbackUrl)
        assertNull(fractional.version)
        assertNull(validatedCallbackUrl(fractional, source))
    }

    @Test
    fun popupIsReservedBeforeDiscoveryAndValidMessageCompletesOnce() =
        runTest {
            val runtime = FakeBrowserOidcRuntime()
            val host = BrowserOidcHost(runtime)
            val request = request()

            assertNull(host.prepare())
            val result = async { host.authorizationHandler.authorize(request) }
            yield()
            assertEquals(request.authorizationUrl, runtime.popup.navigatedTo)

            runtime.emit(
                BrowserOidcMessage("https://attacker.invalid", runtime.popup, "siere-oidc-callback", 1, "ignored"),
            )
            assertFalse(result.isCompleted)
            val callback = "$JS_OIDC_REDIRECT_URI?code=code&state=expected-state"
            runtime.emit(
                BrowserOidcMessage(JS_SAMPLE_ORIGIN, runtime.popup, "siere-oidc-callback", 1, callback),
            )

            assertEquals(callback, result.await())
            assertEquals(1, runtime.listenerRemovals)
            assertEquals(1, runtime.pollStops)
            assertTrue(runtime.popup.isClosed)
            runtime.emit(
                BrowserOidcMessage(JS_SAMPLE_ORIGIN, runtime.popup, "siere-oidc-callback", 1, callback),
            )
            assertEquals(1, runtime.listenerRemovals)
        }

    @Test
    fun popupCloseReturnsStateBoundCancellationAndCleansUp() =
        runTest {
            val runtime = FakeBrowserOidcRuntime()
            val host = BrowserOidcHost(runtime)
            val request = request()
            assertNull(host.prepare())
            val result = async { host.authorizationHandler.authorize(request) }
            yield()

            runtime.popup.close()
            runtime.poll()

            assertEquals(
                "$JS_OIDC_REDIRECT_URI?error=access_denied&error_description=cancelled&state=expected-state",
                result.await(),
            )
            assertEquals(1, runtime.listenerRemovals)
            assertEquals(1, runtime.pollStops)
        }

    @Test
    fun popupClosedDuringDiscoveryCancelsWithoutOpeningAnotherWindow() =
        runTest {
            val runtime = FakeBrowserOidcRuntime()
            val host = BrowserOidcHost(runtime)
            assertNull(host.prepare())
            runtime.popup.close()

            assertEquals(cancellationCallback(request()), host.authorizationHandler.authorize(request()))
            assertEquals(1, runtime.openCalls)
        }

    @Test
    fun blockedPopupStopsBeforeAuthorizationAndFinishClosesReservedPopup() {
        val blocked = BrowserOidcHost(FakeBrowserOidcRuntime(blockPopup = true))
        assertIs<AuthError.PopupBlocked>(blocked.prepare())

        val runtime = FakeBrowserOidcRuntime()
        val host = BrowserOidcHost(runtime)
        assertNull(host.prepare())
        host.finish()
        assertTrue(runtime.popup.isClosed)
        assertEquals(1, runtime.openCalls)
    }

    @Test
    fun secondPreparationDoesNotOpenOrOrphanAnotherPopup() {
        val runtime = FakeBrowserOidcRuntime()
        val host = BrowserOidcHost(runtime)

        assertNull(host.prepare())
        assertIs<AuthError.Unknown>(host.prepare())
        assertEquals(1, runtime.openCalls)
        assertFalse(runtime.popup.isClosed)
        host.finish()
        assertTrue(runtime.popup.isClosed)
    }

    @Test
    fun coroutineCancellationClosesPopupAndCleansRuntimeHooks() =
        runTest {
            val runtime = FakeBrowserOidcRuntime()
            val host = BrowserOidcHost(runtime)
            assertNull(host.prepare())
            val result = async { host.authorizationHandler.authorize(request()) }
            yield()

            result.cancelAndJoin()

            assertTrue(runtime.popup.isClosed)
            assertEquals(1, runtime.listenerRemovals)
            assertEquals(1, runtime.pollStops)
        }

    @Test
    fun navigationFailureCleansListenerTimerAndPopup() =
        runTest {
            val runtime = FakeBrowserOidcRuntime(failNavigation = true)
            val host = BrowserOidcHost(runtime)
            assertNull(host.prepare())

            assertFailsWith<IllegalStateException> {
                host.authorizationHandler.authorize(request())
            }
            host.finish()

            assertTrue(runtime.popup.isClosed)
            assertEquals(1, runtime.listenerRemovals)
            assertEquals(1, runtime.pollStops)
        }

    @Test
    fun pageDisposalClosesActivePopupAndRemovesRuntimeHooks() =
        runTest {
            val runtime = FakeBrowserOidcRuntime()
            val host = BrowserOidcHost(runtime)
            assertNull(host.prepare())
            val result = async { host.authorizationHandler.authorize(request()) }
            yield()

            host.finish()

            assertTrue(runtime.popup.isClosed)
            assertEquals(1, runtime.listenerRemovals)
            assertEquals(1, runtime.pollStops)
            result.cancelAndJoin()
        }

    private fun request() =
        OidcAuthorizationRequest(
            authorizationUrl = "http://127.0.0.1:8080/auth?client_id=test&state=expected-state",
            redirectUri = JS_OIDC_REDIRECT_URI,
        )
}

private class FakeBrowserOidcRuntime(
    private val blockPopup: Boolean = false,
    failNavigation: Boolean = false,
) : BrowserOidcRuntime {
    val popup = FakeBrowserOidcPopup(failNavigation)
    var openCalls = 0
    var listenerRemovals = 0
    var pollStops = 0
    private var listener: ((BrowserOidcMessage) -> Unit)? = null
    private var pollBlock: (() -> Unit)? = null

    override fun openPopup(): BrowserOidcPopup? {
        openCalls += 1
        return if (blockPopup) null else popup
    }

    override fun addMessageListener(listener: (BrowserOidcMessage) -> Unit): () -> Unit {
        this.listener = listener
        return {
            this.listener = null
            listenerRemovals += 1
        }
    }

    override fun pollPopup(block: () -> Unit): () -> Unit {
        pollBlock = block
        return {
            pollBlock = null
            pollStops += 1
        }
    }

    fun emit(message: BrowserOidcMessage) = listener?.invoke(message)

    fun poll() = pollBlock?.invoke()
}

private class FakeBrowserOidcPopup(
    private val failNavigation: Boolean,
) : BrowserOidcPopup {
    override var isClosed: Boolean = false
    override val sourceIdentity: Any
        get() = this
    var navigatedTo: String? = null

    override fun navigate(url: String) {
        if (failNavigation) error("Navigation failed")
        navigatedTo = url
    }

    override fun close() {
        isClosed = true
    }
}
