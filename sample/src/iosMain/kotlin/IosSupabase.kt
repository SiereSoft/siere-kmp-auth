@file:Suppress("ktlint:standard:function-naming")

import dev.siere.auth.sample.displayBackendOrigin
import dev.siere.auth.sample.requirePublishableSupabaseKey
import dev.siere.auth.supabase.SupabaseAuthProvider
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.annotations.SupabaseExperimental
import io.github.jan.supabase.auth.Auth
import io.github.jan.supabase.auth.CodeVerifierCache
import io.github.jan.supabase.auth.FlowType
import io.github.jan.supabase.auth.SessionManager
import io.github.jan.supabase.auth.UrlLauncher
import io.github.jan.supabase.auth.handleDeeplinks
import io.github.jan.supabase.createSupabaseClient
import io.ktor.client.engine.HttpClientEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import platform.Foundation.NSURL
import platform.UIKit.UIViewController

private const val IOS_SUPABASE_CALLBACK_SCHEME = "dev.siere.auth.sample"
private const val IOS_SUPABASE_CALLBACK_HOST = "auth-callback"

/**
 * Owns the single Supabase client used by the iOS sample, including redirect handling.
 * The host application must retain this object for as long as the Compose UI is alive.
 */
@OptIn(SupabaseExperimental::class)
class IosSupabaseHost internal constructor(
    private val client: SupabaseClient,
    private val backendOrigin: String,
) {
    constructor(
        supabaseUrl: String,
        supabasePublishableKey: String,
    ) : this(
        client = createIosSupabaseClient(supabaseUrl, supabasePublishableKey),
        backendOrigin = displayBackendOrigin(supabaseUrl),
    )

    private val closeScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var closed = false

    fun makeViewController(): UIViewController =
        MainViewController(
            supabaseBackendOrigin = backendOrigin,
            configuredSupabaseClient = client,
        )

    /** Returns false without touching auth state when the URL is not this sample's callback. */
    fun handleOpenUrl(url: String): Boolean = routeIosSupabaseCallback(url) { client.handleDeeplinks(it) }

    fun close() {
        if (closed) return
        closed = true
        closeScope.launch {
            try {
                client.close()
            } finally {
                closeScope.cancel()
            }
        }
    }
}

internal fun routeIosSupabaseCallback(
    url: String,
    onAccepted: (NSURL) -> Unit,
): Boolean {
    val nativeUrl = NSURL.URLWithString(url) ?: return false
    if (nativeUrl.scheme != IOS_SUPABASE_CALLBACK_SCHEME || nativeUrl.host != IOS_SUPABASE_CALLBACK_HOST) {
        return false
    }
    onAccepted(nativeUrl)
    return true
}

@OptIn(SupabaseExperimental::class)
internal fun createIosSupabaseClient(
    supabaseUrl: String,
    supabasePublishableKey: String,
    httpEngine: HttpClientEngine? = null,
    testMode: Boolean = false,
    sessionManager: SessionManager? = null,
    codeVerifierCache: CodeVerifierCache? = null,
    urlLauncher: UrlLauncher? = null,
    autoLoadFromStorage: Boolean = !testMode,
    autoSaveToStorage: Boolean = !testMode,
    alwaysAutoRefresh: Boolean = !testMode,
): SupabaseClient =
    createSupabaseClient(
        supabaseUrl = supabaseUrl.trim(),
        supabaseKey = requirePublishableSupabaseKey(supabasePublishableKey),
    ) {
        this.httpEngine = httpEngine
        install(Auth) {
            scheme = IOS_SUPABASE_CALLBACK_SCHEME
            host = IOS_SUPABASE_CALLBACK_HOST
            flowType = FlowType.PKCE
            this.sessionManager = sessionManager
            this.codeVerifierCache = codeVerifierCache
            if (urlLauncher != null) this.urlLauncher = urlLauncher
            this.autoLoadFromStorage = autoLoadFromStorage
            this.autoSaveToStorage = autoSaveToStorage
            this.alwaysAutoRefresh = alwaysAutoRefresh
        }
    }

internal fun iosSupabaseProvider(client: SupabaseClient) = SupabaseAuthProvider(client)
