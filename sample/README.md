# Multiplatform sample

The sample always includes the credential-free Demo provider. Firebase and Supabase appear only
when local configuration is present, so the repository contains no external API keys or hosted
test accounts. The source-controlled `demo` account belongs only to the disposable local Keycloak
fixture used by the OIDC samples.

## Run OpenID Connect on Kotlin/JS

The Kotlin/JS app includes a credential-free **Local OIDC** option backed by the disposable
Keycloak realm in `sample-jvm-oidc`. It uses Authorization Code with PKCE, a browser popup, the
callback `http://127.0.0.1:8081/oidc-callback.html`, and the library's in-memory session store.

From the repository root, start a clean Keycloak realm and build the production browser bundle:

```shell
./gradlew :sample-jvm-oidc:keycloakDown
./gradlew :sample-jvm-oidc:keycloakUp
./gradlew :sample:jsBrowserDistribution
```

Serve that exact distribution from its registered origin:

```shell
python3 -m http.server 8081 --bind 127.0.0.1 \
  --directory sample/build/dist/js/productionExecutable
```

Open `http://127.0.0.1:8081`, select **Local OIDC**, choose **Sign in with OpenID Connect**, and
use:

```text
username: demo
password: demo-password
```

The click reserves the popup before OIDC discovery begins, so normal popup protection can associate
it with the user gesture. The callback document sends the complete callback URL only to the exact
sample origin; the opener also checks the message origin, popup identity, payload shape, and callback
path before passing it to the library. Closing the popup is reported as a normal cancellation.

Choose **Get fresh session** to exercise token refresh, then **Sign out**. Reloading the page loses
the session by design: the sample does not store access, refresh, or ID tokens in browser storage.

Stop the disposable realm afterward:

```shell
./gradlew :sample-jvm-oidc:keycloakDown
```

This loopback HTTP setup is for local development only. A production browser client must use HTTPS,
register its exact callback and allowed web origin with the identity provider, keep the callback
message target and opener checks equally strict, and decide deliberately whether an audited secure
persistence layer is appropriate. This sample does not implement full-page redirect fallback,
silent iframe SSO, background refresh, or provider logout.

## Run OpenID Connect on iOS

The iOS app includes a credential-free **Local OIDC** option backed by the disposable Keycloak realm
in `sample-jvm-oidc`. The host uses `ASWebAuthenticationSession`, the callback
`dev.siere.auth.sample://oidc/callback`, and an iOS Keychain-backed `OidcSessionStore`.

Start Keycloak from the repository root:

```shell
./gradlew :sample-jvm-oidc:keycloakUp
```

Open `iosApp/iosApp.xcodeproj`, run the app on an iOS simulator, select **Local OIDC**, and use:

```text
username: demo
password: demo-password
```

After signing in, terminate and relaunch the app to exercise session restoration from Keychain.
Select **Call protected endpoint** to force a token refresh immediately before sending the bearer
token to Keycloak's `userinfo` endpoint. Sign out, terminate, and relaunch again to confirm the
persisted session was deleted.

The sample's `Info.plist` registers the callback scheme and enables local networking so the
simulator can reach the HTTP-only development realm at `127.0.0.1`. Production clients must use
HTTPS discovery and should remove the local-network exception when they do not need it.

Stop the disposable realm afterward:

```shell
./gradlew :sample-jvm-oidc:keycloakDown
```

## Run Supabase Auth on iOS

The iOS host uses one retained Supabase client, PKCE, and the callback
`dev.siere.auth.sample://auth-callback`.

1. In the Supabase dashboard, enable the authentication methods you want to exercise.
2. Under **Authentication → URL Configuration**, add
   `dev.siere.auth.sample://auth-callback` to **Redirect URLs**.
3. Open `iosApp/iosApp.xcodeproj` in Xcode.
4. Create a personal, unshared copy of the `iOSApp` scheme. Under **Run → Arguments → Environment
   Variables**, add:

   - `SIERE_SUPABASE_URL`: the project URL, such as `https://example.supabase.co`;
   - `SIERE_SUPABASE_PUBLISHABLE_KEY`: a publishable key or legacy anonymous key.

   Never use a secret or service-role key. Do not commit the scheme containing local values.
5. Run the app on an iOS simulator. The **Supabase** provider option appears when both values are
   present.

Email/password sign-in can be exercised directly. OAuth, email confirmation, and password-reset
callbacks return through the registered URL scheme. SwiftUI forwards those URLs with `.onOpenURL`
to the same retained client that started authentication.

Environment variables are convenient for this sample and simulator testing. A production app
should inject public configuration through its reviewed build configuration and use universal links
where appropriate.

## Run the deterministic iOS test

```shell
./gradlew :sample:iosSimulatorArm64Test
```

The tests use Ktor's `MockEngine`, so they require no Supabase project or network connection. They
run as a Kotlin/Native iOS simulator executable and verify:

- the iOS client uses the registered scheme and host with PKCE;
- email sign-in, forced token refresh, password-reset initiation, and sign-out;
- session restoration through an injected session store;
- opaque OIDC session persistence, replacement, and deletion through the Keychain store boundary;
- exact scheme-and-host callback filtering;
- Google PKCE code exchange through the retained iOS host;
- signed-out Google cancellation without a token exchange;
- iOS OIDC browser completion, user cancellation, and coroutine cancellation;
- protected-call behavior: refresh before the request, and at most one forced-refresh retry after a
  `401` when the initial request did not already refresh;
- the publishable key is sent as the `apikey` header;
- Supabase sessions become the expected provider-neutral models and states.

This deterministic test does not replace live acceptance. Before release, repeat the selected flows
against a disposable Supabase project and confirm callback handling, cancellation, session restore,
refresh, and sign-out on the supported iOS versions.

The Kotlin/Native command-line test injects a Keychain client because Security.framework Keychain
access requires an application process. The signed iOS sample is the acceptance path for proving
real Keychain restoration and deletion across process termination.
