@file:Suppress("ktlint:standard:filename")

import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.window.ComposeViewport
import dev.siere.auth.firebase.FirebaseAuthProvider
import dev.siere.auth.firebase.FirebaseWebOptions
import dev.siere.auth.sample.ProviderOption
import dev.siere.auth.sample.SampleApp
import dev.siere.auth.sample.demoProviderOption
import dev.siere.auth.sample.displayBackendOrigin
import dev.siere.auth.sample.publishableSupabaseKeyOrNull
import dev.siere.auth.supabase.SupabaseAuthProvider
import kotlinx.browser.document
import kotlinx.browser.window
import org.jetbrains.skiko.wasm.onWasmReady

@OptIn(ExperimentalComposeUiApi::class)
fun main() {
    onWasmReady {
        val body = document.body ?: return@onWasmReady
        ComposeViewport(body) {
            SampleApp(
                buildList {
                    add(demoProviderOption())
                    firebaseOptionsFromLocalStorage()?.let { options ->
                        add(
                            ProviderOption(
                                name = "Firebase",
                                backendOrigin = displayBackendOrigin(options.authDomain),
                            ) { FirebaseAuthProvider(options) },
                        )
                    }
                    supabaseFromLocalStorage()?.let { (url, key) ->
                        add(
                            ProviderOption(
                                name = "Supabase",
                                backendOrigin = displayBackendOrigin(url),
                            ) {
                                SupabaseAuthProvider(url, key)
                            },
                        )
                    }
                },
            )
        }
    }
}

private fun firebaseOptionsFromLocalStorage(): FirebaseWebOptions? {
    val storage = window.localStorage
    val apiKey = storage.getItem("siere.auth.firebase.apiKey")?.takeIf { it.isNotBlank() } ?: return null
    val authDomain = storage.getItem("siere.auth.firebase.authDomain")?.takeIf { it.isNotBlank() } ?: return null
    val projectId = storage.getItem("siere.auth.firebase.projectId")?.takeIf { it.isNotBlank() } ?: return null
    val applicationId = storage.getItem("siere.auth.firebase.applicationId")?.takeIf { it.isNotBlank() } ?: return null
    return FirebaseWebOptions(apiKey, authDomain, projectId, applicationId)
}

private fun supabaseFromLocalStorage(): Pair<String, String>? {
    val storage = window.localStorage
    val url = storage.getItem("siere.auth.supabase.url")?.takeIf { it.isNotBlank() } ?: return null
    val key =
        publishableSupabaseKeyOrNull(
            storage.getItem("siere.auth.supabase.publishableKey"),
        ) ?: return null
    return url to key
}
