@file:Suppress("ktlint:standard:function-naming")

import dev.siere.auth.SiereAuth
import dev.siere.auth.oidc.OidcAuthorizationHandler
import dev.siere.auth.oidc.OidcAuthorizationRequest
import dev.siere.auth.sample.AuthenticatedCallResult
import dev.siere.auth.sample.SampleBackendResponse
import dev.siere.auth.sample.authenticatedBackendCall
import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import platform.AuthenticationServices.ASWebAuthenticationPresentationContextProvidingProtocol
import platform.AuthenticationServices.ASWebAuthenticationSession
import platform.AuthenticationServices.ASWebAuthenticationSessionErrorCodeCanceledLogin
import platform.AuthenticationServices.ASWebAuthenticationSessionErrorDomain
import platform.Foundation.NSError
import platform.Foundation.NSURL
import platform.UIKit.UIViewController
import platform.UIKit.UIWindow
import platform.darwin.NSObject
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val IOS_OIDC_REDIRECT_URI = "dev.siere.auth.sample://oidc/callback"

/** Owns the iOS browser bridge used by the local OIDC sample. */
class IosOidcHost(
    presentationAnchor: () -> UIWindow?,
) {
    internal val authorizationHandler = IosOidcAuthorizationHandler(presentationAnchor)
    internal val sessionStore =
        IosKeychainOidcSessionStore(
            service = "dev.siere.auth.sample.oidc",
            account = "siere-ios-oidc@http://127.0.0.1:8080/realms/siere",
        )
    private val protectedClient = HttpClient(Darwin)

    fun makeViewController(): UIViewController = MainViewController(oidcHost = this)

    internal suspend fun callProtectedEndpoint(auth: SiereAuth): AuthenticatedCallResult =
        authenticatedBackendCall(
            forceRefreshBeforeCall = true,
            currentSession = auth::currentSession,
        ) { accessToken ->
            val response =
                protectedClient.get(
                    "http://127.0.0.1:8080/realms/siere/protocol/openid-connect/userinfo",
                ) {
                    bearerAuth(accessToken)
                }
            response.bodyAsText()
            SampleBackendResponse(
                statusCode = response.status.value,
                successMessage = "Protected userinfo call accepted a freshly refreshed token",
            )
        }

    fun close() {
        authorizationHandler.close()
        protectedClient.close()
    }
}

internal class IosOidcAuthorizationHandler internal constructor(
    presentationAnchor: () -> UIWindow?,
    private val sessionFactory: IosWebAuthenticationSessionFactory = AppleWebAuthenticationSessionFactory,
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main,
) : OidcAuthorizationHandler {
    private val presentationContext = IosPresentationContext(presentationAnchor)
    private var activeSession: IosWebAuthenticationSession? = null

    override suspend fun authorize(request: OidcAuthorizationRequest): String =
        withContext(mainDispatcher) {
            check(activeSession == null) { "An OIDC authorization request is already active" }
            suspendCancellableCoroutine { continuation ->
                val session =
                    sessionFactory.create(request, presentationContext) { result ->
                        activeSession = null
                        if (!continuation.isActive) return@create
                        when (result) {
                            is IosWebAuthenticationResult.Callback -> continuation.resume(result.url)
                            IosWebAuthenticationResult.Cancelled ->
                                continuation.resume(iosOidcCancellationCallback(request))
                            is IosWebAuthenticationResult.Failure ->
                                continuation.resumeWithException(IllegalStateException(result.message))
                        }
                    }
                activeSession = session
                continuation.invokeOnCancellation {
                    cancelOnMain(session)
                }
                if (!session.start() && continuation.isActive) {
                    activeSession = null
                    continuation.resumeWithException(
                        IllegalStateException("iOS could not start the OIDC browser session"),
                    )
                }
            }
        }

    fun close() {
        activeSession?.let(::cancelOnMain)
    }

    private fun cancelOnMain(session: IosWebAuthenticationSession) {
        val cancel = {
            if (activeSession === session) activeSession = null
            session.cancel()
        }
        if (mainDispatcher.isDispatchNeeded(EmptyCoroutineContext)) {
            mainDispatcher.dispatch(EmptyCoroutineContext) { cancel() }
        } else {
            cancel()
        }
    }
}

internal fun iosOidcCancellationCallback(request: OidcAuthorizationRequest): String {
    val state =
        Regex("(?:[?&])state=([^&#]+)")
            .find(request.authorizationUrl)
            ?.groupValues
            ?.get(1)
            ?: error("OIDC authorization URL omitted state")
    return "${request.redirectUri}?error=access_denied&error_description=cancelled&state=$state"
}

internal sealed interface IosWebAuthenticationResult {
    data class Callback(
        val url: String,
    ) : IosWebAuthenticationResult

    data object Cancelled : IosWebAuthenticationResult

    data class Failure(
        val message: String,
    ) : IosWebAuthenticationResult
}

internal interface IosWebAuthenticationSession {
    fun start(): Boolean

    fun cancel()
}

internal fun interface IosWebAuthenticationSessionFactory {
    fun create(
        request: OidcAuthorizationRequest,
        presentationContext: ASWebAuthenticationPresentationContextProvidingProtocol,
        completion: (IosWebAuthenticationResult) -> Unit,
    ): IosWebAuthenticationSession
}

private object AppleWebAuthenticationSessionFactory : IosWebAuthenticationSessionFactory {
    override fun create(
        request: OidcAuthorizationRequest,
        presentationContext: ASWebAuthenticationPresentationContextProvidingProtocol,
        completion: (IosWebAuthenticationResult) -> Unit,
    ): IosWebAuthenticationSession {
        val authorizationUrl =
            NSURL.URLWithString(request.authorizationUrl)
                ?: error("OIDC authorization URL is invalid")
        val callbackScheme =
            NSURL.URLWithString(request.redirectUri)?.scheme
                ?: error("OIDC redirect URI has no scheme")
        return AppleWebAuthenticationSession(
            authorizationUrl = authorizationUrl,
            callbackScheme = callbackScheme,
            presentationContext = presentationContext,
            completion = completion,
        )
    }
}

private class AppleWebAuthenticationSession(
    authorizationUrl: NSURL,
    callbackScheme: String,
    presentationContext: ASWebAuthenticationPresentationContextProvidingProtocol,
    completion: (IosWebAuthenticationResult) -> Unit,
) : IosWebAuthenticationSession {
    private val session =
        ASWebAuthenticationSession(authorizationUrl, callbackScheme) { callbackUrl, error ->
            completion(callbackUrl.toIosWebAuthenticationResult(error))
        }.apply {
            presentationContextProvider = presentationContext
        }

    override fun start(): Boolean = session.start()

    override fun cancel() {
        session.cancel()
    }
}

private fun NSURL?.toIosWebAuthenticationResult(error: NSError?): IosWebAuthenticationResult =
    when {
        this != null ->
            IosWebAuthenticationResult.Callback(
                absoluteString ?: error("iOS returned an OIDC callback without a URL"),
            )
        error?.run {
            domain == ASWebAuthenticationSessionErrorDomain &&
                code == ASWebAuthenticationSessionErrorCodeCanceledLogin
        } == true -> IosWebAuthenticationResult.Cancelled
        else -> IosWebAuthenticationResult.Failure(error?.localizedDescription ?: "OIDC browser session failed")
    }

private class IosPresentationContext(
    private val presentationAnchor: () -> UIWindow?,
) : NSObject(),
    ASWebAuthenticationPresentationContextProvidingProtocol {
    @Suppress("MaxLineLength") // Objective-C protocol selector is intentionally descriptive.
    override fun presentationAnchorForWebAuthenticationSession(session: ASWebAuthenticationSession): UIWindow? = presentationAnchor()
}

internal fun iosOidcRedirectUri(): String = IOS_OIDC_REDIRECT_URI
