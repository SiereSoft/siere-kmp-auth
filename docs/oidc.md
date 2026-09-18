# OpenID Connect on JVM desktop

`auth-oidc` adds standards-based sign-in to JVM desktop applications through Siere Auth. It uses
Authorization Code Flow with PKCE, opens the system browser, receives the result on an ephemeral
IPv4 loopback port, validates the ID token, and restores encrypted sessions.

This first release targets JVM desktop only.

For a complete credential-free application, use the
[JVM OIDC sample](../sample-jvm-oidc/README.md). It includes a local Keycloak realm, public client,
demo account, Compose Desktop UI, refresh, restoration, and local sign-out.

## Provider registration

Register the application as a **native** or **public** client at the identity provider:

- enable Authorization Code Flow;
- require PKCE with `S256`;
- allow loopback redirects in the form `http://127.0.0.1:<dynamic-port>/callback`;
- issue ID tokens and refresh tokens when requested;
- do not create or embed a client secret.

A secret shipped inside a desktop application is not confidential. Siere deliberately has no
client-secret option for OIDC.

## Dependency

```kotlin
kotlin {
    sourceSets {
        jvmMain.dependencies {
            implementation("dev.siere.auth:auth-core:0.1.0")
            implementation("dev.siere.auth:auth-oidc:0.1.0")
        }
    }
}
```

## Setup

```kotlin
import dev.siere.auth.SiereAuth
import dev.siere.auth.oidc.OidcAuthProvider
import dev.siere.auth.oidc.OidcConfiguration

val auth = SiereAuth(
    OidcAuthProvider(
        OidcConfiguration(
            clientId = "your-public-client-id",
            discoveryUrl =
                "https://identity.example/.well-known/openid-configuration",
            scopes = setOf("profile", "email", "offline_access"),
            providerId = "identity.example",
        ),
    ),
)

val result = auth.signInWithOpenId()
```

The loopback redirect URI is intentionally not configuration. Siere binds `127.0.0.1` on an
available port for each attempt and sends that exact URI in both authorization and token requests.

## Security guarantees

Siere:

- discovers authorization, token, and JWKS endpoints over HTTPS;
- uses fresh cryptographic `state`, nonce, and PKCE verifier values for every attempt;
- binds only to `127.0.0.1` and validates the exact callback path, method, `Host`, and state;
- rejects malformed or duplicate callback parameters and accepts a callback only once;
- returns `no-store`, `no-cache`, and `no-referrer` response headers;
- never places tokens in callback URLs;
- validates ID-token signature, issuer, audience, authorized party, nonce, expiry, `iat`, and `nbf`;
- reloads JWKS when a token references a rotated signing key;
- omits client secrets from every request;
- preserves a refresh token when a provider does not rotate it;
- clears the local session when refresh is rejected as invalid;
- prevents plaintext default session storage with AES-256-GCM and owner-only file permissions;
- redacts tokens from session string representations;
- closes the callback listener on success, timeout, cancellation, or provider shutdown.

Plain HTTP endpoints are rejected. The `allowInsecureHttpForTesting` option accepts HTTP only for
numeric IPv4 or IPv6 loopback hosts so deterministic local tests do not weaken production use.

## Session storage

The default store writes the key and authenticated ciphertext as separate owner-only files below
`~/.siere-auth`. This protects against accidental disclosure and offline reads by other OS users;
it is not a hardware-backed keychain and cannot defend against code already running as the same
user.

Applications that require an OS keychain or enterprise credential vault can implement
`JvmOidcSessionStore` and pass it to `OidcAuthProvider`. Store implementations receive sensitive
plaintext session bytes and must provide confidentiality, integrity, atomic replacement, and safe
deletion.

## Consumer-owned responsibilities

The application remains responsible for:

- registering and configuring the public client correctly;
- choosing scopes and any provider-specific authorization parameters;
- protecting its own process and operating-system account;
- validating the access token at its backend according to that API's issuer and audience rules;
- mapping `AuthError` values to user-facing copy;
- calling `close()` when the auth owner is disposed.

`signOut()` clears Siere's local session. It does not clear the browser's provider cookie or invoke
provider-specific RP-initiated logout.
