# Siere KMP Auth

Provider-neutral authentication for Kotlin Multiplatform. Your application uses one stable API for
identity, sessions, errors, and account linking, then supplies the Firebase, Supabase, or OpenID
Connect adapter that fits its backend.

The current release is **`0.2.1`**.

## Supported providers and targets

`✓` means the adapter is published for that target. `—` means it is not supported by that adapter.
Provider-console or host-app configuration may still be required; follow the linked setup guide.

| Provider | Siere Auth version | Android | iOS | JVM | JavaScript | Wasm |
|---|---:|:---:|:---:|:---:|:---:|:---:|
| [Firebase](auth-firebase/README.md) | `0.2.1` | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Supabase](auth-supabase/README.md) | `0.2.1` | ✓ | ✓ | ✓ | ✓ | ✓ |
| [OpenID Connect](auth-oidc/README.md) | `0.2.1` | ✓ | ✓ | ✓ | ✓ | ✓ |

All multiplatform modules are built with Kotlin `2.4.10`. Android artifacts require API 30 or
newer. The Firebase iOS integration is experimental and is verified with Xcode 26.2.

## Core overview

`auth-core` has no provider or UI dependency. It defines:

- `SiereAuth`, the application-facing authentication facade;
- `AuthUser`, immutable normalized identity data;
- `AuthState`, observable identity state without credentials;
- `AuthSession`, a point-in-time credential snapshot;
- `AuthResult` and `AuthError`, typed success and failure values;
- `PhoneVerificationSession`, the two-step phone verification contract.

Fetch a fresh session immediately before sending a credential to your backend. Do not retain
tokens from `authState`; it intentionally contains identity only. `AuthSession.toString()` redacts
access and refresh tokens.

```kotlin
val auth = SiereAuth(provider)

when (val result = auth.signInWithEmail(email, password)) {
    is AuthResult.Success -> showUser(result.value)
    is AuthResult.Failure -> showError(result.error)
}

when (val session = auth.currentSession(forceRefresh = true)) {
    is AuthResult.Success -> callMyBackend(session.value.accessToken)
    is AuthResult.Failure -> showError(session.error)
}

auth.close()
```

Provider exceptions are normalized into `AuthError`, coroutine cancellation is preserved, and an
operation unavailable on a target returns `AuthError.Unsupported`.

## Installation

Artifacts are published to Siere's GitHub Packages repository. Supply a GitHub Packages token from
local Gradle properties or environment variables; never commit it.

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://maven.pkg.github.com/sieresoft/siere-kmp-auth")
            credentials {
                username = providers.gradleProperty("gpr.user")
                    .orElse(providers.environmentVariable("GITHUB_ACTOR")).orNull
                password = providers.gradleProperty("gpr.key")
                    .orElse(providers.environmentVariable("GITHUB_TOKEN")).orNull
            }
        }
    }
}
```

Add the core API and one provider adapter in `commonMain`:

```kotlin
commonMain.dependencies {
    implementation("dev.siere.auth:auth-core:0.2.1")
    implementation("dev.siere.auth:auth-supabase:0.2.1") // or auth-firebase/auth-oidc
}
```

Continue with the provider you chose:

- [Firebase setup and platform instructions](auth-firebase/README.md)
- [Supabase setup and redirect instructions](auth-supabase/README.md)
- [OpenID Connect setup for all targets](auth-oidc/README.md)

## Modules

| Module | Purpose |
|---|---|
| `auth-core` | Provider-neutral identity, state, session, result, error, and lifecycle contracts. |
| `auth-firebase` | Firebase adapter using GitLive on Android/JVM/JS/iOS and Firebase JS bindings on Wasm. |
| `auth-supabase` | Supabase Auth adapter with a matching Ktor engine for each target. |
| `auth-oidc` | Multiplatform OIDC public client with discovery, PKCE, signed token validation, refresh, and host-owned redirect/storage integration. |
| `sample` | Compose Multiplatform sample with a credential-free Demo provider and local Android OIDC flow. |
| `sample-jvm-oidc` | Compose Desktop OIDC sample with a disposable local Keycloak realm. |

## Samples

The multiplatform sample uses the in-memory **Demo** provider on most targets and a disposable local
Keycloak client on Android. It contains no Siere API keys, Firebase files, or Supabase projects; the
source-controlled Android OIDC client and demo account are only for the loopback development realm.

```shell
./gradlew :sample:jsBrowserDistribution :sample:wasmJsBrowserDistribution
./gradlew :sample:assembleDebug
./gradlew :sample:run
open sample/iosApp/iosApp.xcodeproj
```

The standalone OIDC sample runs against a local Keycloak realm and needs no external account:

```shell
./gradlew :sample-jvm-oidc:keycloakUp
./gradlew :sample-jvm-oidc:run
```

See the [JVM OIDC sample guide](sample-jvm-oidc/README.md) for its demo account and cleanup command.

## Verification

```shell
./gradlew :auth-core:allTests :auth-core:apiCheck \
  :auth-firebase:allTests :auth-firebase:apiCheck \
  :auth-supabase:allTests :auth-supabase:apiCheck \
  :auth-oidc:allTests :auth-oidc:apiCheck \
  :sample:allTests :sample-jvm-oidc:jvmTest
./gradlew staticAnalysis
python3 scripts/verify_no_secrets.py
git diff --check
```

Live Firebase and Supabase acceptance remains separate because it requires disposable configuration
owned by the consuming application.

## License

[Apache-2.0](LICENSE)

---

## Built by Siere Soft

A European software studio building AI-native products and **verifiable agent environments** — small, spec-first. This is one of our open tools.

Studio: **[sieresoft.com](https://sieresoft.com)** · **[hello@sieresoft.com](mailto:hello@sieresoft.com)**

Building agents, evals, or payments and want help? **[Book a call →](https://sieresoft.com/contact)**

Licensed under Apache-2.0. Contributions welcome — see [CONTRIBUTING](CONTRIBUTING.md).
