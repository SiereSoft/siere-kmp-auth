# Multiplatform sample

The sample always includes the credential-free Demo provider. Provider-backed options only appear
when their local configuration is present, so the repository does not contain API keys or test
accounts.

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
- exact scheme-and-host callback filtering;
- Google PKCE code exchange through the retained iOS host;
- signed-out Google cancellation without a token exchange;
- the publishable key is sent as the `apikey` header;
- Supabase sessions become the expected provider-neutral models and states.

This deterministic test does not replace live acceptance. Before release, repeat the selected flows
against a disposable Supabase project and confirm callback handling, cancellation, session restore,
refresh, and sign-out on the supported iOS versions.
