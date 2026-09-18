# OpenID Connect provider

Use `auth-oidc` for standards-based OpenID Connect on Android, iOS, JVM, JavaScript, and Wasm.
The adapter uses Authorization Code Flow with PKCE, validates signed ID tokens, refreshes access
tokens, and can restore sessions through a host-supplied secure store.

[Back to the project overview](../README.md)

## Feature support

| Capability | Android | iOS | JVM | JavaScript | Wasm |
|---|:---:|:---:|:---:|:---:|:---:|
| Provider discovery over HTTPS | ✓ | ✓ | ✓ | ✓ | ✓ |
| Authorization Code Flow with PKCE | ✓ | ✓ | ✓ | ✓ | ✓ |
| RS256/384/512 and ES256/384/512 ID-token validation | ✓ | ✓ | ✓ | ✓ | ✓ |
| Refresh and session restoration | ✓ | ✓ | ✓ | ✓ | ✓ |
| Host-owned browser/deep-link handling | ✓ | ✓ | ✓ | ✓ | ✓ |
| Encrypted default storage | — | — | JVM | — | — |

The protocol is shared across all targets. Redirect UI and durable credential storage remain host
application responsibilities because their secure implementations depend on an Activity, iOS
presentation context and Keychain, browser navigation model, or application-specific vault.

## Register the application

Register each application as a **native** or **public** client:

- enable Authorization Code Flow;
- require PKCE with `S256`;
- register the exact redirect URI used by that target;
- issue ID tokens and refresh tokens when requested;
- do not create or embed a client secret.

A secret distributed in a mobile, desktop, or browser application is not confidential. The adapter
deliberately has no client-secret option.

## Add the dependency

After adding the GitHub Packages repository from the [project installation guide](../README.md#installation):

```kotlin
commonMain.dependencies {
    implementation("dev.siere.auth:auth-core:0.2.0")
    implementation("dev.siere.auth:auth-oidc:0.2.0")
}
```

## Create a provider on every target

The common factory takes the exact registered redirect URI and an `OidcAuthorizationHandler`.
The handler opens the authorization URL in the platform's secure browser, waits for the redirect,
and returns the complete callback URL:

```kotlin
val auth = SiereAuth(
    OidcAuthProvider(
        configuration = OidcConfiguration(
            clientId = "your-public-client-id",
            discoveryUrl =
                "https://identity.example/.well-known/openid-configuration",
            scopes = setOf("profile", "email", "offline_access"),
            providerId = "identity.example",
        ),
        redirectUri = "com.example.app://oauth/callback",
        authorizationHandler = appOidcAuthorizationHandler,
        sessionStore = appSecureOidcSessionStore,
    ),
)

val result = auth.signInWithOpenId()
```

The handler receives both the generated authorization URL and redirect URI. Return only a callback
for that request. Siere validates the exact redirect URI, state, optional callback issuer,
authorization code, PKCE verifier, and ID-token nonce before accepting a session.

Platform integration typically looks like this:

- **Android:** launch a Custom Tab and resume the suspended handler from the registered app link or
  custom-scheme Activity intent.
- **iOS:** use `ASWebAuthenticationSession` and return its callback URL.
- **JavaScript/Wasm:** use a popup and return its callback URL after a same-origin callback or a
  narrowly validated `postMessage`. The provider's discovery, token, and JWKS endpoints must allow
  the application's origin through CORS.
- **JVM with a custom redirect:** open the browser and bridge the registered callback back to the
  handler, as on the other targets.

`InMemoryOidcSessionStore` is the cross-platform default. It supports refresh while the provider is
alive but intentionally does not persist tokens. Implement `OidcSessionStore` with Android Keystore,
iOS Keychain, or another platform credential vault when restart restoration is required. Do not put
refresh tokens in browser `localStorage`.

## JVM desktop convenience flow

The existing JVM factory remains available. It opens the system browser, binds an ephemeral IPv4
loopback callback on `127.0.0.1`, and uses encrypted file storage by default:

```kotlin
val auth = SiereAuth(
    OidcAuthProvider(
        OidcConfiguration(
            clientId = "your-public-client-id",
            discoveryUrl =
                "https://identity.example/.well-known/openid-configuration",
            scopes = setOf("profile", "email", "offline_access"),
        ),
    ),
)
```

Register loopback redirects in the form `http://127.0.0.1:<dynamic-port>/callback`. Applications
that require an OS keychain or enterprise vault can still implement `JvmOidcSessionStore` and pass
it to this overload.

## Security guarantees

Siere:

- requires HTTPS for discovery, authorization, token, and JWKS endpoints;
- generates fresh cryptographic state, nonce, and PKCE values for every attempt;
- validates the exact callback URI and state;
- never places tokens in callback URLs;
- validates ID-token signature, issuer, audience, authorized party, nonce, expiry, `iat`, and `nbf`;
- reloads JWKS when a token cannot be verified with the cached signing keys;
- rejects RSA signing keys smaller than 2048 bits;
- preserves a refresh token when a provider does not rotate it;
- clears the local session when refresh is rejected as invalid.

Plain HTTP discovery is rejected. `allowInsecureHttpForTesting` accepts HTTP only for numeric IPv4
or IPv6 loopback hosts so local deterministic tests do not weaken production use.

## Application responsibilities

- Register and configure each public client and redirect URI correctly.
- Implement browser/deep-link completion without accepting callbacks for unrelated requests.
- Store durable sessions only in an appropriate credential vault.
- Choose scopes and provider-specific authorization parameters.
- Validate access tokens at the backend for that API's issuer and audience.
- Map `AuthError` values to user-facing messages.
- Call `auth.close()` when the owner is disposed.

`signOut()` deletes Siere's local session. It does not clear the provider's browser cookie or invoke
provider-specific RP-initiated logout.
