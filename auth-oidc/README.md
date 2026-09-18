# OpenID Connect provider for JVM desktop

Use `auth-oidc` for a standards-based OpenID Connect provider on JVM desktop. Version `0.1.0` uses
Authorization Code Flow with PKCE, opens the system browser, receives the result on an ephemeral
IPv4 loopback port, validates the ID token, and restores encrypted sessions.

This adapter is JVM-only.

[Back to the project overview](../README.md)

## Feature support

| Capability | JVM desktop |
|---|:---:|
| Provider discovery over HTTPS | ✓ |
| Authorization Code Flow with PKCE | ✓ |
| Signed ID-token validation | ✓ |
| Refresh and session restoration | ✓ |
| Encrypted default session storage | ✓ |
| Local sign-out | ✓ |

For a complete credential-free application, use the
[JVM OIDC sample](../sample-jvm-oidc/README.md). It includes a local Keycloak realm, public client,
demo account, Compose Desktop UI, refresh, restoration, and local sign-out.

## Register the application

Register the desktop application as a **native** or **public** client at the identity provider:

- enable Authorization Code Flow;
- require PKCE with `S256`;
- allow loopback redirects in the form `http://127.0.0.1:<dynamic-port>/callback`;
- issue ID tokens and refresh tokens when requested;
- do not create or embed a client secret.

A secret shipped inside a desktop application is not confidential. The adapter deliberately has no
client-secret option.

## Add the dependency

After adding the GitHub Packages repository from the [project installation guide](../README.md#installation):

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

## Create the provider

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

The redirect URI is intentionally not configurable. Siere binds `127.0.0.1` on an available port
for every attempt and sends that exact URI in the authorization and token requests.

## Security guarantees

Siere:

- discovers authorization, token, and JWKS endpoints over HTTPS;
- generates fresh cryptographic state, nonce, and PKCE values for every attempt;
- validates the exact callback path, method, host, and state and accepts a callback only once;
- never places tokens in callback URLs;
- validates ID-token signature, issuer, audience, authorized party, nonce, expiry, `iat`, and `nbf`;
- reloads JWKS when a token references a rotated signing key;
- preserves a refresh token when a provider does not rotate it;
- clears the local session when refresh is rejected as invalid;
- closes the callback listener on success, timeout, cancellation, or provider shutdown.

Plain HTTP discovery is rejected. `allowInsecureHttpForTesting` accepts HTTP only for numeric IPv4
or IPv6 loopback hosts so local deterministic tests do not weaken production use.

## Session storage

The default store writes the key and AES-256-GCM authenticated ciphertext as separate owner-only
files below `~/.siere-auth`. This protects against accidental disclosure and offline reads by other
OS users. It is not a hardware-backed keychain and cannot defend against code running as the same
user.

Applications that require an OS keychain or enterprise vault can implement `JvmOidcSessionStore`
and pass it to `OidcAuthProvider`. A custom store receives sensitive plaintext session bytes and
must provide confidentiality, integrity, atomic replacement, and safe deletion.

## Application responsibilities

- Register and configure the public client correctly.
- Choose the scopes and provider-specific authorization parameters.
- Validate access tokens at the backend for that API's issuer and audience.
- Map `AuthError` values to user-facing messages.
- Call `auth.close()` when the owner is disposed.

`signOut()` deletes Siere's local session. It does not clear the provider's browser cookie or invoke
provider-specific RP-initiated logout.
