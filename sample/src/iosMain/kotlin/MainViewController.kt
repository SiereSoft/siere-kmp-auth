@file:Suppress("FunctionNaming", "ktlint:standard:function-naming")

import androidx.compose.ui.window.ComposeUIViewController
import dev.siere.auth.firebase.FirebaseAuthProvider
import dev.siere.auth.firebase.GoogleSignInPresenter
import dev.siere.auth.oidc.OidcAuthProvider
import dev.siere.auth.oidc.OidcConfiguration
import dev.siere.auth.sample.ProviderOption
import dev.siere.auth.sample.SampleApp
import dev.siere.auth.sample.demoProviderOption
import dev.siere.auth.supabase.SupabaseAuthProvider
import io.github.jan.supabase.SupabaseClient

/**
 * The sample's Compose entry point for an iOS app shell. Pass the Swift-side
 * GoogleSignIn bridge (or null to leave Google flows unsupported). The Swift app shell must opt in
 * to Firebase only after calling `FirebaseApp.configure()` with its own plist.
 */
fun MainViewController(
    firebaseConfigured: Boolean = false,
    googleSignIn: GoogleSignInPresenter? = null,
    supabaseBackendOrigin: String? = null,
    configuredSupabaseClient: SupabaseClient? = null,
    oidcHost: IosOidcHost? = null,
) = ComposeUIViewController {
    SampleApp(
        buildList {
            add(demoProviderOption())
            if (firebaseConfigured) {
                add(ProviderOption("Firebase") { FirebaseAuthProvider(googleSignIn) })
            }
            if (configuredSupabaseClient != null) {
                add(
                    ProviderOption("Supabase", backendOrigin = supabaseBackendOrigin) {
                        SupabaseAuthProvider(configuredSupabaseClient)
                    },
                )
            }
            if (oidcHost != null) {
                add(
                    ProviderOption(
                        name = "Local OIDC",
                        backendOrigin = "http://127.0.0.1:8080",
                        authenticatedCall = oidcHost::callProtectedEndpoint,
                    ) {
                        OidcAuthProvider(
                            configuration =
                                OidcConfiguration(
                                    clientId = "siere-ios-oidc",
                                    discoveryUrl =
                                        "http://127.0.0.1:8080/realms/siere/" +
                                            ".well-known/openid-configuration",
                                    providerId = "keycloak",
                                    allowInsecureHttpForTesting = true,
                                ),
                            redirectUri = iosOidcRedirectUri(),
                            authorizationHandler = oidcHost.authorizationHandler,
                            sessionStore = oidcHost.sessionStore,
                        )
                    },
                )
            }
        },
    )
}
