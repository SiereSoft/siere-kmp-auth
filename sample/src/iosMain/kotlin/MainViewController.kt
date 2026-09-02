@file:Suppress("ktlint:standard:function-naming")

import androidx.compose.ui.window.ComposeUIViewController
import dev.siere.auth.firebase.FirebaseAuthProvider
import dev.siere.auth.firebase.GoogleSignInPresenter
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
    configuredSupabaseClient: SupabaseClient? = null,
) = ComposeUIViewController {
    SampleApp(
        buildList {
            add(demoProviderOption())
            if (firebaseConfigured) {
                add(ProviderOption("Firebase") { FirebaseAuthProvider(googleSignIn) })
            }
            if (configuredSupabaseClient != null) {
                add(
                    ProviderOption("Supabase") {
                        SupabaseAuthProvider(configuredSupabaseClient)
                    },
                )
            }
        },
    )
}
