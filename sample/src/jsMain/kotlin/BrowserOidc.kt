@file:Suppress("TooGenericExceptionCaught", "UnsafeCastFromDynamic")

import dev.siere.auth.AuthError
import dev.siere.auth.oidc.OidcAuthorizationHandler
import dev.siere.auth.oidc.OidcAuthorizationRequest
import kotlinx.browser.window
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import org.w3c.dom.MessageEvent
import org.w3c.dom.Window
import org.w3c.dom.events.EventListener
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal const val JS_SAMPLE_ORIGIN = "http://127.0.0.1:8081"
internal const val JS_OIDC_REDIRECT_URI = "$JS_SAMPLE_ORIGIN/oidc-callback.html"
internal const val JS_OIDC_CLIENT_ID = "siere-js-oidc"
internal const val JS_OIDC_DISCOVERY_URL =
    "http://127.0.0.1:8080/realms/siere/.well-known/openid-configuration"

private const val CALLBACK_MESSAGE_TYPE = "siere-oidc-callback"
private const val CALLBACK_MESSAGE_VERSION = 1
private const val POPUP_NAME = "siere-oidc-login"
private const val POPUP_FEATURES = "popup=yes,width=520,height=720,resizable=yes,scrollbars=yes"
private const val POPUP_POLL_MILLIS = 250

internal class BrowserOidcHost(
    private val runtime: BrowserOidcRuntime = DomBrowserOidcRuntime,
) {
    private var attempt: BrowserOidcAttempt? = null

    val authorizationHandler = OidcAuthorizationHandler(::authorize)

    /** Must be called directly from the click handler while browser user activation is available. */
    fun prepare(): AuthError? =
        if (attempt != null) {
            AuthError.Unknown("An OpenID Connect sign-in is already active")
        } else {
            val popup = runtime.openPopup()
            if (popup == null) {
                AuthError.PopupBlocked()
            } else {
                attempt = BrowserOidcAttempt(popup, runtime)
                null
            }
        }

    /** Releases a popup reserved before discovery when discovery or token exchange fails. */
    fun finish() {
        attempt?.close()
        attempt = null
    }

    private suspend fun authorize(request: OidcAuthorizationRequest): String {
        val active = attempt ?: error("The OIDC popup was not prepared from a user gesture")
        if (active.popup.isClosed) {
            return cancellationCallback(request)
        }
        return try {
            active.awaitCallback(request)
        } finally {
            if (attempt === active) attempt = null
            active.close()
        }
    }
}

private class BrowserOidcAttempt(
    val popup: BrowserOidcPopup,
    private val runtime: BrowserOidcRuntime,
) {
    private var removeListener: (() -> Unit)? = null
    private var stopPolling: (() -> Unit)? = null
    private var completed = false

    suspend fun awaitCallback(request: OidcAuthorizationRequest): String =
        suspendCancellableCoroutine { continuation ->
            fun complete(callbackUrl: String) {
                if (completed || !continuation.isActive) return
                completed = true
                cleanup()
                continuation.resume(callbackUrl)
            }

            removeListener =
                runtime.addMessageListener { message ->
                    val callbackUrl = validatedCallbackUrl(message, popup.sourceIdentity, request.redirectUri)
                    if (callbackUrl != null) complete(callbackUrl)
                }
            stopPolling =
                runtime.pollPopup {
                    if (popup.isClosed) complete(cancellationCallback(request))
                }
            continuation.invokeOnCancellation {
                completed = true
                cleanup()
                if (!popup.isClosed) popup.close()
            }

            try {
                popup.navigate(request.authorizationUrl)
            } catch (failure: Throwable) {
                completed = true
                cleanup()
                if (continuation.isActive) continuation.resumeWithException(failure)
            }
        }

    fun close() {
        completed = true
        cleanup()
        if (!popup.isClosed) popup.close()
    }

    private fun cleanup() {
        removeListener?.invoke()
        removeListener = null
        stopPolling?.invoke()
        stopPolling = null
    }
}

internal fun validatedCallbackUrl(
    message: BrowserOidcMessage,
    expectedSource: Any,
    redirectUri: String = JS_OIDC_REDIRECT_URI,
): String? {
    val trustedEnvelope =
        message.origin == JS_SAMPLE_ORIGIN &&
            message.source === expectedSource &&
            message.type == CALLBACK_MESSAGE_TYPE &&
            message.version == CALLBACK_MESSAGE_VERSION
    return if (trustedEnvelope) {
        message.callbackUrl?.takeIf { isExactOidcCallback(it, redirectUri) }
    } else {
        null
    }
}

internal data class BrowserOidcMessage(
    val origin: String,
    val source: Any?,
    val type: String?,
    val version: Int?,
    val callbackUrl: String?,
)

internal interface BrowserOidcPopup {
    val isClosed: Boolean
    val sourceIdentity: Any

    fun navigate(url: String)

    fun close()
}

internal interface BrowserOidcRuntime {
    fun openPopup(): BrowserOidcPopup?

    fun addMessageListener(listener: (BrowserOidcMessage) -> Unit): () -> Unit

    fun pollPopup(block: () -> Unit): () -> Unit
}

private object DomBrowserOidcRuntime : BrowserOidcRuntime {
    override fun openPopup(): BrowserOidcPopup? {
        val popup = window.open("", POPUP_NAME, POPUP_FEATURES)
        return popup?.let(::DomBrowserOidcPopup)
    }

    override fun addMessageListener(listener: (BrowserOidcMessage) -> Unit): () -> Unit {
        val eventListener =
            EventListener { event ->
                val message = event as? MessageEvent ?: return@EventListener
                listener(browserOidcMessage(message.origin, message.source, message.data))
            }
        window.addEventListener("message", eventListener)
        return { window.removeEventListener("message", eventListener) }
    }

    override fun pollPopup(block: () -> Unit): () -> Unit {
        val pollId = window.setInterval(block, POPUP_POLL_MILLIS)
        return { window.clearInterval(pollId) }
    }
}

internal fun browserOidcMessage(
    origin: String,
    source: Any?,
    data: Any?,
): BrowserOidcMessage {
    val payload = data?.asDynamic()
    val payloadType: Any? = payload?.type
    val payloadVersion: Any? = payload?.version
    val payloadCallbackUrl: Any? = payload?.callbackUrl
    val numericVersion = (payloadVersion as? Number)?.toDouble()
    val exactVersion =
        numericVersion
            ?.takeIf { it.isFinite() && it % 1.0 == 0.0 }
            ?.toInt()
    return BrowserOidcMessage(
        origin = origin,
        source = source,
        type = payloadType as? String,
        version = exactVersion,
        callbackUrl = payloadCallbackUrl as? String,
    )
}

private class DomBrowserOidcPopup(
    private val window: Window,
) : BrowserOidcPopup {
    override val isClosed: Boolean
        get() = window.closed

    override val sourceIdentity: Any
        get() = window

    override fun navigate(url: String) {
        window.location.href = url
    }

    override fun close() = window.close()
}

internal fun isExactOidcCallback(
    callbackUrl: String,
    redirectUri: String = JS_OIDC_REDIRECT_URI,
): Boolean {
    if ('#' in callbackUrl) return false
    val base = callbackUrl.substringBefore('?')
    return base == redirectUri
}

internal fun cancellationCallback(request: OidcAuthorizationRequest): String {
    val state =
        Regex("(?:[?&])state=([^&#]+)")
            .find(request.authorizationUrl)
            ?.groupValues
            ?.get(1)
            ?: throw CancellationException("OIDC authorization URL omitted state")
    return "${request.redirectUri}?error=access_denied&error_description=cancelled&state=$state"
}
