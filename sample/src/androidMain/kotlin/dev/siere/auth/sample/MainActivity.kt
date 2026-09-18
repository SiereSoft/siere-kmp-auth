package dev.siere.auth.sample

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import dev.siere.auth.oidc.OidcAuthProvider
import dev.siere.auth.oidc.OidcAuthorizationHandler
import dev.siere.auth.oidc.OidcAuthorizationRequest
import dev.siere.auth.oidc.OidcConfiguration
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred

class MainActivity : ComponentActivity() {
    private val authorizationHandler = AndroidOidcAuthorizationHandler(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SampleApp(listOf(demoProviderOption(), localOidcProviderOption()))
        }
        acceptOidcCallback(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        acceptOidcCallback(intent)
    }

    override fun onDestroy() {
        authorizationHandler.cancel()
        super.onDestroy()
    }

    private fun acceptOidcCallback(intent: Intent) {
        intent.dataString?.let(authorizationHandler::complete)
    }

    private fun localOidcProviderOption(): ProviderOption =
        ProviderOption(
            name = "Local OIDC",
            backendOrigin = "http://127.0.0.1:8080",
        ) {
            OidcAuthProvider(
                configuration =
                    OidcConfiguration(
                        clientId = "siere-android-oidc",
                        discoveryUrl =
                            "http://127.0.0.1:8080/realms/siere/" +
                                ".well-known/openid-configuration",
                        providerId = "keycloak",
                        allowInsecureHttpForTesting = true,
                    ),
                redirectUri = OIDC_REDIRECT_URI,
                authorizationHandler = authorizationHandler,
            )
        }
}

private class AndroidOidcAuthorizationHandler(
    private val activity: ComponentActivity,
) : OidcAuthorizationHandler {
    private var pendingCallback: CompletableDeferred<String>? = null

    override suspend fun authorize(request: OidcAuthorizationRequest): String {
        check(pendingCallback == null) { "An OIDC authorization request is already active" }
        val callback = CompletableDeferred<String>()
        pendingCallback = callback
        activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(request.authorizationUrl)))
        return try {
            callback.await()
        } finally {
            if (pendingCallback === callback) pendingCallback = null
        }
    }

    fun complete(callbackUrl: String) {
        if (callbackUrl.substringBefore('?').substringBefore('#') == OIDC_REDIRECT_URI) {
            pendingCallback?.complete(callbackUrl)
        }
    }

    fun cancel() {
        pendingCallback?.cancel(CancellationException("Android activity was destroyed"))
        pendingCallback = null
    }
}

private const val OIDC_REDIRECT_URI = "dev.siere.auth.sample://oauth/callback"
