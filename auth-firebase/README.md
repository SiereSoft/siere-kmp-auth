# Firebase provider

Use `auth-firebase` when Firebase Authentication owns the user account and session. Version `0.2.1`
supports Android, iOS, JVM, JavaScript, and Wasm.

[Back to the project overview](../README.md)

## Feature support

`✓` means the operation is implemented on that target. `—` means it returns
`AuthError.Unsupported`. A check mark does not remove the need to enable the sign-in method and
configure the application in Firebase.

| Capability | Android | iOS | JVM | JavaScript | Wasm |
|---|:---:|:---:|:---:|:---:|:---:|
| Observe and restore auth state | ✓ | ✓ | ✓ | ✓ | ✓ |
| Email sign-in, sign-up, and password reset | ✓ | ✓ | ✓ | ✓ | ✓ |
| Anonymous sign-in | ✓ | ✓ | ✓ | ✓ | ✓ |
| Fresh session and sign-out | ✓ | ✓ | ✓ | ✓ | ✓ |
| Google sign-in and linking | ✓ | ✓ | ✓ | ✓ | ✓ |
| Apple sign-in and linking | ✓ | ✓ | ✓ | ✓ | ✓ |
| Phone sign-in and linking | ✓ | ✓ | ✓ | ✓ | ✓ |

## Add the dependency

After adding the GitHub Packages repository from the [project installation guide](../README.md#installation):

```kotlin
commonMain.dependencies {
    implementation("dev.siere.auth:auth-core:0.2.1")
    implementation("dev.siere.auth:auth-firebase:0.2.1")
}
```

The adapter uses the Siere-verified GitLive Firebase bridge
`3.0.0-alpha01-siere.37da67e3`. Treat that bridge as pre-release until the required changes are
available in a stable upstream GitLive release.

## Firebase console setup

1. Create or select a Firebase project and register each application target.
2. Enable every authentication method the application will expose.
3. Add the target's authorized domains, redirect URLs, URL schemes, and Apple capability as
   required by Firebase.
4. Use Firebase test phone numbers during development; do not automate real SMS delivery in tests.
5. Keep OAuth JSON, Apple `.p8` keys, service-account files, and broker credentials out of source
   control.

## JavaScript and Wasm

Pass the public Firebase web configuration to the provider:

```kotlin
val provider = FirebaseAuthProvider(
    FirebaseWebOptions(
        apiKey = consumerConfig.apiKey,
        authDomain = consumerConfig.authDomain,
        projectId = consumerConfig.projectId,
        applicationId = consumerConfig.applicationId,
    ),
)
val auth = SiereAuth(provider)
```

Add the deployed origin to Firebase's authorized domains. Google and Apple use popup flows. Phone
authentication creates an invisible reCAPTCHA verifier for each attempt. The
`appVerificationDisabledForTesting` option is only for Firebase's documented test setup and must not
be enabled in production.

## Android

Add the consuming app's `google-services.json`, apply Firebase's Google Services configuration, and
enable the required sign-in methods. The library requires Android API 30 or newer.

Email, anonymous, session, and sign-out operations can use the zero-argument provider. Interactive
Google, Apple, and phone flows need the current resumed `Activity`:

```kotlin
val provider = FirebaseAuthProvider(
    activityProvider = AndroidActivityProvider { currentResumedActivity },
    googleServerClientId = consumerConfig.googleWebClientId,
)
```

`AndroidActivityProvider` must return a current, non-finishing activity and must not retain a
destroyed activity. Google uses Credential Manager, Apple uses Firebase's OAuth Custom Tab flow,
and phone authentication supports automatic verification as well as SMS-code confirmation. Obtain
explicit user consent before linking Apple to an existing account.

## iOS

The host app must call `FirebaseApp.configure()` before constructing the provider. Apple sign-in is
implemented with AuthenticationServices and a cryptographically secure Firebase nonce. Enable the
Sign in with Apple capability and obtain explicit consent before linking an Apple identity.

Google sign-in needs a small Swift-side presenter because the GoogleSignIn SDK owns presentation:

```kotlin
val provider = FirebaseAuthProvider(googleSignIn = googleSignInPresenter)
```

Implement `GoogleSignInPresenter` around
`GIDSignIn.sharedInstance.signIn(withPresenting:)`, then return the ID and access tokens through its
callbacks. Omit the presenter when Google is not enabled.

Use Kotlin's direct Xcode integration for a static shared framework. From the consuming project:

```shell
XCODEPROJ_PATH=/path/to/iosApp.xcodeproj \
GRADLE_PROJECT_PATH=:shared \
./gradlew :shared:integrateEmbedAndSign :shared:integrateLinkagePackage
```

Commit `KotlinMultiplatformLinkedPackage`, SwiftPM lockfiles, and the generated Xcode project
changes. FirebaseAuth and FirebaseCore resolve through Swift Package Manager; no CocoaPods workspace
is used. This integration is experimental, requires Kotlin 2.4 or newer, and is verified with Xcode
26.2.

## JVM desktop

Initialize GitLive Firebase before constructing the provider. The repository's
[`DesktopMain.kt`](../sample/src/jvmMain/kotlin/dev/siere/auth/sample/DesktopMain.kt) shows the full
initialization, including a replaceable session store.

Email and anonymous operations work with `FirebaseAuthProvider()`. Google requires a Desktop OAuth
client and uses the system browser, an ephemeral `127.0.0.1` callback, Authorization Code Flow, and
PKCE:

```kotlin
val provider = FirebaseAuthProvider(
    JvmGoogleAuthConfig(
        clientId = consumerConfig.googleDesktopClientId,
    ),
)
```

Public desktop clients should omit `clientSecret`. A controlled, non-distributed JVM deployment may
supply one only when its OAuth client requires authentication. Never embed a confidential secret in
a distributed desktop application.

Apple and phone flows require a consumer implementation of `JvmFirebaseAuthBroker`:

```kotlin
val provider = FirebaseAuthProvider(
    googleAuthConfig = JvmGoogleAuthConfig(consumerConfig.googleDesktopClientId),
    authBroker = consumerHostedFirebaseAuthBroker,
)
```

The trusted broker owns the hosted HTTPS Apple return, Apple client-secret signing, Firebase Web
reCAPTCHA/app verification, rate limits, expiry, and replay prevention. Bind every result to its
initiating state, PKCE verifier, and operation; use short expiry and one-time redemption; and keep
tokens out of URLs and logs. Siere does not host a shared broker or accept server signing keys.

## Lifecycle and security

- Treat `auth.authState` as the source of identity truth.
- Call `currentSession(forceRefresh = true)` immediately before an authenticated backend request.
- Call `auth.close()` when the owner is disposed.
- Never ship service-account credentials or an Apple private key in a client application.
- Expect interactive provider flows to require real consumer-owned console configuration even
  though deterministic adapter tests pass without it.
