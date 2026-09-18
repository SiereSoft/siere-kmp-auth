@file:Suppress("FunctionNaming", "LongMethod")

package dev.siere.auth.sample.oidc

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.SiereAuth
import dev.siere.auth.oidc.OidcAuthProvider
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

fun main() {
    val configuration = SampleConfiguration.fromEnvironment()
    application {
        val auth =
            remember {
                SiereAuth(OidcAuthProvider(configuration.toOidcConfiguration()))
            }
        DisposableEffect(auth) {
            onDispose(auth::close)
        }
        Window(
            onCloseRequest = ::exitApplication,
            title = "Siere KMP Auth — OpenID Connect",
        ) {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    OidcSample(auth, configuration)
                }
            }
        }
    }
}

@Composable
private fun OidcSample(
    auth: SiereAuth,
    configuration: SampleConfiguration,
) {
    val state by auth.authState.collectAsState()
    val scope = rememberCoroutineScope()
    var message by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("JVM OpenID Connect", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Authorization Code Flow with PKCE, an ephemeral loopback callback, " +
                "validated ID tokens, encrypted restoration, and refresh.",
        )
        Text(
            "Provider: ${configuration.providerId}",
            style = MaterialTheme.typography.labelLarge,
        )

        when (val current = state) {
            AuthState.Loading -> LoadingCard()
            AuthState.SignedOut ->
                SignedOutCard(
                    busy = busy,
                    onSignIn = {
                        scope.launch {
                            busy = true
                            message = null
                            message = auth.signInWithOpenId().message("Signed in successfully")
                            busy = false
                        }
                    },
                )

            is AuthState.SignedIn ->
                SignedInCard(
                    user = current.user,
                    busy = busy,
                    onRefresh = {
                        scope.launch {
                            busy = true
                            message = null
                            message =
                                when (val result = auth.currentSession(forceRefresh = true)) {
                                    is AuthResult.Success -> {
                                        val expiry = result.value.expiresAtEpochMillis?.formatTimestamp() ?: "unknown"
                                        "Session refreshed. Access token expires at $expiry."
                                    }

                                    is AuthResult.Failure -> result.error.message
                                }
                            busy = false
                        }
                    },
                    onSignOut = {
                        scope.launch {
                            busy = true
                            message = auth.signOut().message("Local session cleared")
                            busy = false
                        }
                    },
                )
        }

        message?.let {
            Text(it, color = MaterialTheme.colorScheme.primary)
        }

        Spacer(Modifier.weight(1f))
        Text(
            "Demo login: demo / demo-password",
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            "No client secret is used. Tokens are never rendered by this sample.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun LoadingCard() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CircularProgressIndicator()
            Spacer(Modifier.width(16.dp))
            Text("Restoring the encrypted session…")
        }
    }
}

@Composable
private fun SignedOutCard(
    busy: Boolean,
    onSignIn: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp)) {
            Text("Signed out", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(8.dp))
            Text("The system browser will open. Return here after authenticating.")
            Spacer(Modifier.height(16.dp))
            Button(onClick = onSignIn, enabled = !busy) {
                Text(if (busy) "Waiting for browser…" else "Sign in with OpenID Connect")
            }
        }
    }
}

@Composable
private fun SignedInCard(
    user: AuthUser,
    busy: Boolean,
    onRefresh: () -> Unit,
    onSignOut: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp)) {
            Text("Signed in", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(8.dp))
            Text(user.displayName ?: "No display name")
            Text(user.email ?: "No email claim")
            Text("UID: ${user.uid}", style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = onRefresh, enabled = !busy) {
                    Text("Refresh session")
                }
                OutlinedButton(onClick = onSignOut, enabled = !busy) {
                    Text("Sign out locally")
                }
            }
        }
    }
}

private fun <T> AuthResult<T>.message(success: String): String =
    when (this) {
        is AuthResult.Success -> success
        is AuthResult.Failure -> error.message
    }

private fun Long.formatTimestamp(): String =
    DateTimeFormatter
        .ofPattern("yyyy-MM-dd HH:mm:ss z")
        .withZone(ZoneId.systemDefault())
        .format(Instant.ofEpochMilli(this))
