# OpenID Connect in Kotlin/JS: Popup Sign-In with PKCE

*Use a user-gesture popup, an exact-origin callback page, and Siere KMP Auth to complete an OIDC Authorization Code flow in Compose for Web.*

After JVM, Android, and iOS, the next target for the OpenID Connect sample was Kotlin/JS.

The OIDC protocol did not need another implementation. [Siere KMP Auth](https://github.com/sieresoft/siere-kmp-auth) already handles discovery, PKCE, code exchange, refresh, and signed ID token validation in shared code. The browser still has to open the authorization page and return the callback URL to that shared code.

One browser rule shaped the whole integration: `window.open()` must run while the click still has user activation.

If discovery starts first and the popup opens after a suspension point, the browser may block it. By then the OIDC operation is already running, but the user has nowhere to sign in.

The working flow opens a blank popup directly in the Compose button handler, keeps that exact `WindowProxy`, and navigates it after discovery finishes.

## The local setup

I used the same disposable Keycloak server as the other samples. The Kotlin/JS client is public, uses Authorization Code with PKCE `S256`, and has one callback and one allowed web origin:

```json
{
  "clientId": "siere-js-oidc",
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "implicitFlowEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": [
    "http://127.0.0.1:8081/oidc-callback.html"
  ],
  "webOrigins": [
    "http://127.0.0.1:8081"
  ],
  "attributes": {
    "pkce.code.challenge.method": "S256"
  }
}
```

Both arrays are intentionally exact. `localhost`, wildcard origins, and a callback without `oidc-callback.html` are different configurations.

The sample configuration points the library at Keycloak discovery:

```kotlin
OidcAuthProvider(
    configuration =
        OidcConfiguration(
            clientId = "siere-js-oidc",
            discoveryUrl =
                "http://127.0.0.1:8080/realms/siere/" +
                    ".well-known/openid-configuration",
            providerId = "keycloak",
            allowInsecureHttpForTesting = true,
        ),
    redirectUri = "http://127.0.0.1:8081/oidc-callback.html",
    authorizationHandler = browserOidcHost.authorizationHandler,
)
```

`allowInsecureHttpForTesting` exists for this loopback setup. A deployed browser client should use HTTPS.

The library installation and current target setup live in the [Siere KMP Auth README](https://github.com/sieresoft/siere-kmp-auth#installation), so the instructions do not freeze a dependency version.

## Open the popup before starting discovery

The Compose button normally launches a coroutine and calls `signInWithOpenId()`. That is too late for a browser popup. I added two sample-level hooks to the provider option:

```kotlin
data class ProviderOption(
    val name: String,
    val backendOrigin: String? = null,
    val prepareOpenIdSignIn: (() -> AuthError?)? = null,
    val finishOpenIdSignIn: (() -> Unit)? = null,
    val create: () -> AuthProvider,
)
```

The click calls `prepareOpenIdSignIn` before `scope.launch`:

```kotlin
onClick = {
    val option = options.getOrNull(created.activeIndex)
    val preparationError = option?.prepareOpenIdSignIn?.invoke()

    if (preparationError != null) {
        status = preparationError.userFacingMessage()
    } else {
        openIdSignInInProgress = true
        scope.launch {
            try {
                when (val result = auth.signInWithOpenId()) {
                    is AuthResult.Success -> status = null
                    is AuthResult.Failure -> status = result.error.userFacingMessage()
                }
            } finally {
                option?.finishOpenIdSignIn?.invoke()
                openIdSignInInProgress = false
            }
        }
    }
}
```

The preparation method performs the only `window.open()` call:

```kotlin
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
```

`runtime.openPopup()` is a small test seam over the browser API:

```kotlin
override fun openPopup(): BrowserOidcPopup? {
    val popup = window.open("", POPUP_NAME, POPUP_FEATURES)
    return popup?.let(::DomBrowserOidcPopup)
}
```

The popup starts blank. Once the library completes discovery and builds the authorization URL, the handler navigates the same popup to Keycloak.

If `window.open()` returns `null`, the sample shows “Allow popups for this site and try again.” It does not start discovery or leave an OIDC operation waiting for a callback that cannot arrive.

## Return the callback without exposing it to another origin

Keycloak redirects the popup to a small static page served by the Kotlin/JS distribution:

```html
<script>
    (() => {
        const openerOrigin = "http://127.0.0.1:8081";
        const callbackUrl = window.location.href;
        window.history.replaceState(null, "", window.location.pathname);
        if (window.opener) {
            const message = { type: "siere-oidc-callback", version: 1, callbackUrl };
            window.opener.postMessage(message, openerOrigin);
        }
    })();
</script>
```

The page captures the complete URL, removes the query from its visible history entry, and sends one typed and versioned message to the exact opener origin. It does not render or log the authorization code.

The callback page does not close itself. `postMessage` and popup-close polling run as separate browser tasks, so closing immediately could let the poll report cancellation before the opener receives the message. The opener closes the popup only after it accepts the validated callback.

The opener does not trust a message because it has the right shape. It checks the event origin, the sending window, the message type and version, and the exact callback path:

```kotlin
val trustedEnvelope =
    message.origin == JS_SAMPLE_ORIGIN &&
        message.source === expectedSource &&
        message.type == CALLBACK_MESSAGE_TYPE &&
        message.version == CALLBACK_MESSAGE_VERSION

return if (trustedEnvelope) {
    message.callbackUrl?.takeIf {
        '#' !in it && it.substringBefore('?') == JS_OIDC_REDIRECT_URI
    }
} else {
    null
}
```

Checking `message.source` binds the callback to the popup opened for this attempt. Another same-origin tab cannot finish it. The shared OIDC code then validates the callback again, including `state`, issuer, code, and ID token nonce.

## Treat a closed popup as cancellation

A user can close the popup before Keycloak returns. The bridge polls `popup.closed` every 250 milliseconds and produces a callback tied to the active OIDC state:

```kotlin
private fun cancellationCallback(request: OidcAuthorizationRequest): String {
    val state =
        Regex("(?:[?&])state=([^&#]+)")
            .find(request.authorizationUrl)
            ?.groupValues
            ?.get(1)
            ?: throw CancellationException("OIDC authorization URL omitted state")

    return "${request.redirectUri}" +
        "?error=access_denied&error_description=cancelled&state=$state"
}
```

This sends cancellation through the same callback validator as a provider error. The public result becomes `AuthError.Cancelled` instead of a browser-specific exception.

There is another timing case. The user can close the blank popup while discovery is still running. The handler checks `popup.closed` before navigation, returns the same state-bound cancellation, and never opens a replacement window.

Every terminal path removes the `message` listener, stops the close poll, releases the active attempt, and closes the popup if it is still open. The `finishOpenIdSignIn` hook also closes a popup reserved before a discovery or token failure.

## Keep browser storage out of the sample

The sample uses `InMemoryOidcSessionStore`. Refresh works while the page stays open, but a reload loses the session.

That behavior is deliberate. Access tokens, refresh tokens, and ID tokens do not belong in callback URLs, console logs, or casual `localStorage` entries. An application that needs browser persistence should make that decision with its threat model and an audited storage design, rather than inherit it from a demo.

## Run it

Start a clean Keycloak container so the new client is imported, then build the production distribution:

```shell
./gradlew :sample-jvm-oidc:keycloakDown
./gradlew :sample-jvm-oidc:keycloakUp
./gradlew :sample:jsBrowserDistribution
```

Serve the generated files from the registered origin:

```shell
python3 -m http.server 8081 --bind 127.0.0.1 \
  --directory sample/build/dist/js/productionExecutable
```

Open `http://127.0.0.1:8081` and use the disposable account:

```text
username: demo
password: demo-password
```

I tested the production distribution in Chrome with normal popup protection. The popup opened from the Compose click, Keycloak returned through `oidc-callback.html`, and the app displayed `Signed in as Siere Demo`. Forced refresh completed, and sign-out returned the UI to `Signed out`. DevTools showed four Skiko WebGL capability warnings, but no errors, CORS failures, mixed-content failures, or token-bearing logs.

The browser tests also cover blocked popups, wrong origins, wrong popup sources, malformed payloads, wrong callback paths, popup closure, duplicate messages, and listener and timer cleanup. The Keycloak fixture test locks down the public client, exact redirect, exact web origin, disabled implicit and password flows, and PKCE `S256`.

The complete sample and its run instructions are in [Siere KMP Auth](https://github.com/sieresoft/siere-kmp-auth/tree/master/sample). Stop the disposable server when you are done:

```shell
./gradlew :sample-jvm-oidc:keycloakDown
```

---

Medium topics: Kotlin, Kotlin Multiplatform, Kotlin/JS, OpenID Connect, Keycloak
