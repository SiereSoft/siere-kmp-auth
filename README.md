# Siere KMP Auth

Provider-neutral authentication for Kotlin Multiplatform clients. The API targets
Android, JVM, JavaScript, Kotlin/Wasm, and iOS, with Firebase and Supabase adapters plus a
credential-free Compose Multiplatform sample.

> **Status:** `0.0.1` initial release. Live provider flows require configuration owned by the
> consuming application. The Firebase adapter depends on the
> Siere-verified GitLive Firebase bridge `3.0.0-alpha01-siere.37da67e3`; consumers should treat its
> ABI and behavior as pre-release until the bridge changes are accepted upstream and a stable
> upstream release is available.

## Modules

| Module | Purpose |
|---|---|
| `auth-core` | Provider-neutral API: normalized identity, observable auth state, credential snapshots, typed results/errors, phone challenge, and lifecycle. No provider or UI dependency. |
| `auth-firebase` | Firebase adapter using GitLive on Android/JVM/JS/iOS and Firebase JS bindings on Wasm. |
| `auth-supabase` | Supabase Auth adapter with a matching Ktor engine for each target. |
| `sample` | Compose sample with a credential-free Demo provider and optional consumer-supplied browser/iOS configuration. |

## Core contract

`AuthUser` is immutable identity data. `AuthState` contains identity state only and never carries
tokens. Fetch a point-in-time `AuthSession` immediately before sending a credential to your own
backend; providers refresh expired credentials, or honor `forceRefresh`, first.

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

Provider exceptions are normalized into `AuthError`; coroutine cancellation is not swallowed.
Unsupported target-specific flows return `AuthError.Unsupported`. `AuthSession.toString()` always
redacts access and refresh tokens.

Provider-owned coroutine scopes use an injectable `DispatcherProvider`. Production callers can use
`DefaultDispatcherProvider`, which selects platform-appropriate dispatchers (including native IO
pools on Android, JVM, and iOS); tests can direct every lane to one test dispatcher:

```kotlin
class TestDispatcherProvider(
    dispatcher: CoroutineDispatcher,
) : DispatcherProvider {
    override val main = dispatcher
    override val default = dispatcher
    override val io = dispatcher
    override val unconfined = dispatcher
}

val provider = SupabaseAuthProvider(
    supabaseUrl = url,
    supabaseKey = publishableKey,
    dispatcherProvider = TestDispatcherProvider(testSchedulerDispatcher),
)
```

## Support matrix

Legend: **Yes** = implemented and covered by deterministic tests; **Config** = implemented but its
interactive provider acceptance flow needs consumer-owned console/app configuration; **No** =
returns `AuthError.Unsupported` on that target.

### Firebase

| Capability | JS | Wasm | Android | iOS | JVM |
|---|---:|---:|---:|---:|---:|
| Observe/restore state | Config | Config | Config | Config | Config |
| Email sign-in/sign-up/reset | Config | Config | Config | Config | Config |
| Anonymous sign-in | Config | Config | Config | Config | Config |
| Fresh session and sign-out | Config | Config | Config | Config | Config |
| Google sign-in/link | Config | Config | Config | Config | Config |
| Apple sign-in/link | Config | Config | Config | Config | Config |
| Phone sign-in/link | Config | Config | Config | Config | Config |

iOS Apple support uses AuthenticationServices and a cryptographically secure Firebase nonce. Apps
must obtain explicit user consent before linking Apple to an existing account. iOS Google support requires the host app to supply a
`GoogleSignInPresenter`; the adapter does not bundle a reusable OAuth client. Firebase native
linkage is inherited through Swift Package Manager from the GitLive adapter. The Apple integration
is experimental and requires Kotlin 2.4+ and Xcode 26.2+. CI pins Xcode
26.2; the same integration also passed locally with Kotlin 2.4.10 and Xcode 26.0.1.

Android interactive flows require `FirebaseAuthProvider(AndroidActivityProvider, googleServerClientId)`.
The activity provider must return the current resumed, non-finishing activity and must not retain a
destroyed activity. Google uses Credential Manager, Apple uses Firebase's OAuth Custom Tab flow,
and phone auth supports automatic verification as well as SMS-code confirmation. Apple linking
also requires explicit user consent in the app UI.

JVM Google sign-in and linking use the system browser, an ephemeral loopback callback bound to
`127.0.0.1`, Authorization Code with PKCE, and the consumer's Google Desktop OAuth client. JVM Apple
and phone flows require a consumer implementation of `JvmFirebaseAuthBroker`. That trusted boundary
owns the hosted HTTPS Apple return, Apple client-secret signing, Firebase Web reCAPTCHA/app
verification, rate limits, expiry, and replay prevention. Browser callbacks carry only opaque
single-use codes; the broker redeems them before returning a short-lived Firebase assertion to the
library. Do not commit OAuth JSON, Apple `.p8` keys, or broker credentials.

### Supabase

Email, phone sign-in, anonymous, session, and sign-out flows use Supabase Auth directly on all five
targets. Supabase phone credential linking currently returns `AuthError.Unsupported` because its
upstream phone-change verification is not safely account-unique. Google/Apple sign-in and linking
are OAuth redirect flows. Browser consumers may use the URL/key factory. Android and iOS consumers
must retain a configured `SupabaseClient`, install Auth with their callback scheme/host, forward the
returning deep link to that same client, and pass it to `SupabaseAuthProvider(client)`. The transition
wait is bounded; always treat `authState` as the source of truth across navigation.

Deterministic tests validate mapping, error codes, token refresh decisions, metadata, and redirect
transition behavior. Live Supabase acceptance remains consumer-configuration-gated.

## Installation

Add the Siere GitHub Packages repository. Siere Auth and its exact verified Firebase bridge
artifacts are published together in this repository. Use a GitHub Packages token through local
Gradle properties or environment variables; never commit it.

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

Depend on the provider-neutral core and the adapters required by the application:

```kotlin
commonMain.dependencies {
    implementation("dev.siere.auth:auth-core:0.0.1")
    implementation("dev.siere.auth:auth-supabase:0.0.1") // or auth-firebase
}
```

Create Supabase with a project URL and a client-safe publishable key (or legacy anonymous key):

```kotlin
val provider = SupabaseAuthProvider(
    supabaseUrl = consumerConfig.supabaseUrl,
    supabaseKey = consumerConfig.supabasePublishableKey,
)
```

Never put a Supabase secret/service-role key in a client application.

For JS and Wasm Firebase:

```kotlin
val provider = FirebaseAuthProvider(
    FirebaseWebOptions(
        apiKey = consumerConfig.apiKey,
        authDomain = consumerConfig.authDomain,
        projectId = consumerConfig.projectId,
        applicationId = consumerConfig.applicationId,
    )
)
```

JVM uses `FirebaseAuthProvider()` after the host application configures Firebase. To enable Google
sign-in and linking, construct it with consumer-owned desktop OAuth configuration:

```kotlin
val provider = FirebaseAuthProvider(
    JvmGoogleAuthConfig(
        clientId = consumerConfig.googleDesktopClientId,
        // Optional: supply clientSecret only when the OAuth client requires it.
    ),
    authBroker = consumerHostedFirebaseAuthBroker, // Required only for Apple/phone.
)
```

Public Desktop OAuth clients should omit `clientSecret`. A controlled, non-distributed JVM
deployment may pass it as a named argument when its OAuth client requires authentication. PKCE is
used in both cases. Never embed a confidential secret in a distributed Desktop application; perform
the code exchange through consumer-owned trusted infrastructure when the provider requires one.

The library does not host a shared Siere broker or accept server signing keys. A broker implementation
must use TLS, bind each result to its initiating state/PKCE verifier and operation, enforce short
expiry and one-time redemption, and keep tokens out of URLs and logs.

Android apps that need interactive flows pass an `AndroidActivityProvider` and their Firebase Web
OAuth client ID; non-interactive Android use may keep the zero-argument factory. On iOS, call
`FirebaseApp.configure()` in the host and create `FirebaseAuthProvider(googleSignIn)`; omit the
presenter when Google flows are not enabled. Use Kotlin's direct Xcode integration for the shared
static framework; FirebaseAuth and FirebaseCore resolve transitively through SwiftPM.

Configure that integration once from the consuming project, using its Xcode project and shared KMP
module paths:

```shell
XCODEPROJ_PATH=/path/to/iosApp.xcodeproj \
GRADLE_PROJECT_PATH=:shared \
./gradlew :shared:integrateEmbedAndSign :shared:integrateLinkagePackage
```

Commit the generated `KotlinMultiplatformLinkedPackage`, SwiftPM lockfiles, and Xcode project
changes. The framework exported by `:shared` must remain static. The generated Xcode build phase
runs `:shared:embedAndSignAppleFrameworkForXcode`; no CocoaPods workspace is used.

## Running the credential-free sample

The sample starts with the in-memory **Demo** provider when no consumer configuration is present;
otherwise it selects the first configured provider so restored sessions are immediately visible. It
ships no Siere API keys, Firebase JSON/plist, signing assets, OAuth client, Supabase project, or test
account.

```shell
# Browser production distributions
./gradlew :sample:jsBrowserDistribution :sample:wasmJsBrowserDistribution

# Android debug APK
./gradlew :sample:assembleDebug

# Desktop JVM (Demo unless the environment variables below are supplied)
./gradlew :sample:run

# iOS project (Swift Package Manager + Kotlin direct integration)
open sample/iosApp/iosApp.xcodeproj
```

For a local Desktop Firebase run, supply `SIERE_SAMPLE_FIREBASE_API_KEY`,
`SIERE_SAMPLE_FIREBASE_APP_ID`, `SIERE_SAMPLE_FIREBASE_PROJECT_ID`, and
`SIERE_SAMPLE_GOOGLE_CLIENT_ID`. `SIERE_SAMPLE_GOOGLE_CLIENT_SECRET` is an optional local
compatibility input and should be omitted for a public Desktop client; environment injection does
not make it safe to redistribute. The sample's file-backed session store exists only to verify
restart restoration; production applications should use operating-system credential storage. Set
`SIERE_SAMPLE_STORAGE_DIRECTORY` to isolate or discard the sample session data.

Android is intentionally Demo-only. The checked-in iOS shell is also Demo-only; a consumer may pass
its own Firebase/Supabase configuration through `MainViewController`.

Browser provider options appear only after all required values are set in that browser's
`localStorage`:

```javascript
localStorage.setItem("siere.auth.firebase.apiKey", "<public web API key>")
localStorage.setItem("siere.auth.firebase.authDomain", "<project>.firebaseapp.com")
localStorage.setItem("siere.auth.firebase.projectId", "<project id>")
localStorage.setItem("siere.auth.firebase.applicationId", "<web app id>")

localStorage.setItem("siere.auth.supabase.url", "https://<project>.supabase.co")
localStorage.setItem("siere.auth.supabase.publishableKey", "<publishable or anon key>")
```

These are client identifiers, not server secrets, but `localStorage` is developer-controlled input,
not a trusted production configuration channel. Code executing on the same origin, browser
extensions, or another user of a shared browser profile can replace it. The sample therefore shows
the active authentication origin prominently whenever Firebase or Supabase is selected. For any
deployed sample or application, inject the reviewed public client configuration at build/deploy time
and apply the normal XSS and browser-extension threat model instead of relying on mutable storage.

Provider-console setup such as authorized domains, OAuth redirect URLs, Apple capabilities, and
Firebase test phone numbers is also consumer-owned. `.swiftpm-locks/` is a disposable, ignored
SwiftPM checkout/cache used by local verification; remove it whenever disk space matters and let the
verification script resolve the pinned packages again.

## Verification

Credential-free deterministic checks:

```shell
./gradlew :auth-core:allTests :auth-core:apiCheck \
  :auth-firebase:allTests :auth-firebase:apiCheck \
  :auth-supabase:allTests :auth-supabase:apiCheck \
  :sample:allTests
./gradlew staticAnalysis
./gradlew :sample:assembleDebug \
  :sample:createDistributable :sample:jsBrowserDistribution :sample:wasmJsBrowserDistribution
python3 scripts/verify_no_secrets.py
git diff --check
```

The repository CI repeats deterministic library/API/browser/Android checks on Linux and native iOS
tests plus the SwiftPM-integrated sample build on macOS. Live Firebase/Supabase acceptance is kept
separate because it must use disposable configuration supplied by the consuming developer.

## License

[Apache-2.0](LICENSE)

---

## Built by Siere Soft

A European software studio building AI-native products and **verifiable agent environments** — small, spec-first. This is one of our open tools.

Studio: **[sieresoft.com](https://sieresoft.com)** · **[hello@sieresoft.com](mailto:hello@sieresoft.com)**

Building agents, evals, or payments and want help? **[Book a call →](https://sieresoft.com/contact)**

Licensed under Apache-2.0. Contributions welcome — see [CONTRIBUTING](CONTRIBUTING.md).
