package dev.siere.auth.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import dev.siere.auth.AuthError
import dev.siere.auth.AuthProvider
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthState
import dev.siere.auth.AuthUser
import dev.siere.auth.PhoneVerificationSession
import dev.siere.auth.SiereAuth
import kotlinx.coroutines.launch

/** A pluggable backend the sample can switch to at runtime. */
data class ProviderOption(
    val name: String,
    val backendOrigin: String? = null,
    val create: () -> AuthProvider,
)

private const val URL_SCHEME_SEPARATOR_LENGTH = 3

/** Extracts a display-only origin from consumer-supplied browser configuration. */
internal fun displayBackendOrigin(configuredEndpoint: String): String {
    val endpoint = configuredEndpoint.trim().trimEnd('/')
    val schemeSeparator = endpoint.indexOf("://")
    val authorityStart =
        if (schemeSeparator >= 0) {
            schemeSeparator + URL_SCHEME_SEPARATOR_LENGTH
        } else {
            0
        }
    val suffixStart =
        endpoint
            .substring(authorityStart)
            .indexOfAny(charArrayOf('/', '?', '#'))
            .takeIf { it >= 0 }
            ?.plus(authorityStart)
            ?: endpoint.length
    val origin = endpoint.substring(0, suffixStart)
    return if (schemeSeparator >= 0) origin else "https://$origin"
}

internal data class ProviderCreation(
    val provider: AuthProvider,
    val activeIndex: Int,
    val errorMessage: String? = null,
)

internal fun createProviderSafely(
    options: List<ProviderOption>,
    requestedIndex: Int,
): ProviderCreation {
    val requested = options.getOrNull(requestedIndex)
    if (requested != null) {
        try {
            return ProviderCreation(requested.create(), requestedIndex)
        } catch (_: Throwable) {
            // Invalid local configuration or SDK initialization must not take down Demo mode.
        }
    }
    val demoIndex = options.indexOfFirst { it.name == "Demo" }.coerceAtLeast(0)
    return ProviderCreation(
        provider = DemoAuthProvider(),
        activeIndex = demoIndex,
        errorMessage = requested?.let { "Could not start ${it.name}. Demo remains active." },
    )
}

@Composable
fun SampleApp(options: List<ProviderOption>) {
    var selectedIndex by remember(options) { mutableStateOf(initialProviderIndex(options)) }
    val created = remember(options, selectedIndex) { createProviderSafely(options, selectedIndex) }
    val auth = remember(created) { SiereAuth(created.provider) }
    DisposableEffect(auth) {
        onDispose { auth.close() }
    }
    val state = auth.authState.collectAsState()
    val scope = rememberCoroutineScope()

    var status by remember(auth) { mutableStateOf(created.errorMessage) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var phoneNumber by remember { mutableStateOf("") }
    var phoneSession by remember(auth) { mutableStateOf<PhoneVerificationSession?>(null) }
    var smsCode by remember { mutableStateOf("") }

    LaunchedEffect(state.value, phoneSession) {
        val session = phoneSession ?: return@LaunchedEffect
        val signedIn = state.value as? AuthState.SignedIn ?: return@LaunchedEffect
        if (signedIn.user.phoneNumber == session.phoneNumber) {
            phoneSession = null
            smsCode = ""
            status = null
        }
    }

    fun run(block: suspend () -> AuthResult<AuthUser>) {
        scope.launch {
            when (val result = block()) {
                is AuthResult.Success -> status = null
                is AuthResult.Failure -> status = result.error.userFacingMessage()
            }
        }
    }

    MaterialTheme {
        Surface {
            Column(
                modifier =
                    Modifier
                        .fillMaxSize()
                        .windowInsetsPadding(WindowInsets.safeDrawing)
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Siere KMP Auth", style = MaterialTheme.typography.headlineMedium)

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    options.forEachIndexed { index, option ->
                        FilterChip(
                            selected = index == created.activeIndex,
                            onClick = { selectedIndex = index },
                            label = { Text(option.name) },
                        )
                    }
                }

                Text(
                    "Demo is credential-free. Firebase and Supabase appear only after local " +
                        "consumer configuration is supplied.",
                    style = MaterialTheme.typography.bodySmall,
                )

                options.getOrNull(created.activeIndex)?.backendOrigin?.let { backendOrigin ->
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        shape = MaterialTheme.shapes.medium,
                    ) {
                        Text(
                            text = "Active ${options[created.activeIndex].name} backend: $backendOrigin",
                            modifier =
                                Modifier
                                    .padding(horizontal = 16.dp, vertical = 12.dp)
                                    .semantics { contentDescription = "Active authentication backend" },
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.titleSmall,
                        )
                    }
                }

                Text(
                    text =
                        when (val current = state.value) {
                            is AuthState.Loading -> "Restoring session…"
                            is AuthState.SignedOut -> "Signed out"
                            is AuthState.SignedIn ->
                                "Signed in as " + (
                                    current.user.displayName
                                        ?: current.user.email
                                        ?: current.user.phoneNumber
                                        ?: if (current.user.isAnonymous) "guest ${current.user.uid}" else current.user.uid
                                )
                        },
                    style = MaterialTheme.typography.titleMedium,
                )

                ElevatedButton(onClick = { run { auth.signInWithGoogle() } }, modifier = buttonWidth()) {
                    Text("Sign in with Google")
                }
                ElevatedButton(onClick = { run { auth.signInWithApple() } }, modifier = buttonWidth()) {
                    Text("Sign in with Apple")
                }
                ElevatedButton(onClick = { run { auth.signInAnonymously() } }, modifier = buttonWidth()) {
                    Text("Continue as guest")
                }
                ElevatedButton(onClick = { run { auth.linkWithGoogle() } }, modifier = buttonWidth()) {
                    Text("Link Google account")
                }
                ElevatedButton(onClick = { run { auth.linkWithApple() } }, modifier = buttonWidth()) {
                    Text("Link Apple account")
                }

                ElevatedButton(
                    modifier = buttonWidth(),
                    onClick = {
                        scope.launch {
                            when (val result = auth.currentSession(forceRefresh = true)) {
                                is AuthResult.Success -> {
                                    status = "Fresh session ready for ${result.value.user.uid}"
                                }
                                is AuthResult.Failure -> status = result.error.userFacingMessage()
                            }
                        }
                    },
                ) {
                    Text("Get fresh session")
                }

                OutlinedTextField(
                    modifier = Modifier.semantics { contentDescription = "Email address" },
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("Email") },
                    singleLine = true,
                )
                OutlinedTextField(
                    modifier = Modifier.semantics { contentDescription = "Password" },
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ElevatedButton(onClick = { run { auth.signInWithEmail(email, password) } }) {
                        Text("Sign in")
                    }
                    ElevatedButton(onClick = { run { auth.signUpWithEmail(email, password) } }) {
                        Text("Sign up")
                    }
                }
                ElevatedButton(
                    modifier = buttonWidth(),
                    onClick = {
                        scope.launch {
                            status =
                                when (val result = auth.sendPasswordReset(email)) {
                                    is AuthResult.Success -> "Password reset requested"
                                    is AuthResult.Failure -> result.error.userFacingMessage()
                                }
                        }
                    },
                ) {
                    Text("Send password reset")
                }

                OutlinedTextField(
                    modifier = Modifier.semantics { contentDescription = "Phone number" },
                    value = phoneNumber,
                    onValueChange = { phoneNumber = it },
                    label = { Text("Phone number") },
                    singleLine = true,
                )
                ElevatedButton(
                    modifier = buttonWidth(),
                    onClick = {
                        scope.launch {
                            val result =
                                if (state.value is AuthState.SignedIn) {
                                    auth.startPhoneLinking(phoneNumber)
                                } else {
                                    auth.startPhoneSignIn(phoneNumber)
                                }
                            when (result) {
                                is AuthResult.Success -> {
                                    phoneSession = result.value
                                    status = "Phone verification started"
                                }
                                is AuthResult.Failure -> status = result.error.userFacingMessage()
                            }
                        }
                    },
                ) {
                    Text(
                        if (state.value is AuthState.SignedIn) "Link phone number" else "Sign in with phone",
                    )
                }

                phoneSession?.let { session ->
                    OutlinedTextField(
                        modifier = Modifier.semantics { contentDescription = "Verification code" },
                        value = smsCode,
                        onValueChange = { smsCode = it },
                        label = { Text("Verification code") },
                        singleLine = true,
                    )
                    ElevatedButton(
                        modifier = buttonWidth(),
                        onClick = {
                            scope.launch {
                                when (val result = session.confirm(smsCode)) {
                                    is AuthResult.Success -> {
                                        phoneSession = null
                                        smsCode = ""
                                        status = null
                                    }
                                    is AuthResult.Failure -> status = result.error.userFacingMessage()
                                }
                            }
                        },
                    ) {
                        Text("Verify code")
                    }
                }

                ElevatedButton(
                    modifier = buttonWidth(),
                    onClick = {
                        scope.launch {
                            when (val result = auth.signOut()) {
                                is AuthResult.Success -> {
                                    phoneSession = null
                                    status = null
                                }
                                is AuthResult.Failure -> status = result.error.userFacingMessage()
                            }
                        }
                    },
                ) {
                    Text("Sign out")
                }

                status?.let {
                    Text(it, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

internal fun initialProviderIndex(options: List<ProviderOption>): Int =
    options
        .indexOfFirst { it.name != "Demo" }
        .takeIf { it >= 0 }
        ?: 0

private fun buttonWidth(): Modifier = Modifier.widthIn(min = 240.dp)

private fun AuthError.userFacingMessage(): String =
    when (this) {
        is AuthError.Cancelled -> "The sign-in flow was cancelled."
        is AuthError.PopupBlocked -> "Allow popups for this site and try again."
        is AuthError.Network -> "The request could not complete. Check your connection and try again."
        is AuthError.InvalidCredentials -> "The supplied credentials are invalid."
        is AuthError.UserNotFound -> "No matching account was found."
        is AuthError.EmailAlreadyInUse -> "An account already exists for this email."
        is AuthError.WeakPassword -> "Choose a stronger password."
        is AuthError.InvalidPhoneNumber -> "Enter a valid phone number including country code."
        is AuthError.InvalidVerificationCode -> "The verification code is invalid or expired."
        is AuthError.CredentialAlreadyInUse -> "That sign-in method belongs to another account."
        is AuthError.ProviderDisabled -> "This sign-in method is not configured for this project."
        is AuthError.BillingRequired -> "This provider requires billing for that operation."
        is AuthError.RegionBlocked -> "The provider does not allow this destination."
        is AuthError.NotSignedIn -> "Sign in before performing that operation."
        is AuthError.AuthStateChanged -> "The signed-in account changed. Start the operation again."
        is AuthError.RequiresRecentLogin -> "Sign in again before performing that operation."
        is AuthError.Unsupported -> "This operation is unavailable on the selected platform."
        is AuthError.Unknown -> "Authentication failed. Check the provider configuration and logs."
    }
