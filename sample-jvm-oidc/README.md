# JVM OpenID Connect sample

This sample runs Siere KMP Auth against a local Keycloak realm. It requires no external account,
client secret, API key, billing account, or paid service.

## Run

From the repository root:

```shell
./gradlew :sample-jvm-oidc:keycloakUp
./gradlew :sample-jvm-oidc:run
```

Click **Sign in with OpenID Connect** and use:

```text
username: demo
password: demo-password
```

The first command starts Keycloak on `127.0.0.1:8080` and imports the realm from
`keycloak/siere-realm.json`. The client is public, requires PKCE `S256`, and accepts only
`http://127.0.0.1/callback`, which permits Siere's ephemeral loopback port without accepting
another host or callback path.

Stop it when finished:

```shell
./gradlew :sample-jvm-oidc:keycloakDown
```

## Run the Android sample

Start an emulator, expose the loopback-only Keycloak port to it, and install the sample:

```shell
adb reverse tcp:8080 tcp:8080
./gradlew :sample:installDebug
adb shell am start -n dev.siere.auth.sample/.MainActivity
```

Select **Local OIDC**, tap **Sign in with OpenID Connect**, and use the same demo credentials.
The Android client is public, requires PKCE `S256`, and accepts only
`dev.siere.auth.sample://oauth/callback`. Cleartext traffic is enabled only in this local sample so
the emulator can use the loopback development realm; deployed apps should use an HTTPS issuer.

The source-controlled development credentials in this directory protect only the loopback-bound,
disposable realm. They are intentionally public and must never be reused in a deployed Keycloak
installation. Keycloak's bootstrap administrator is also local-only and uses `admin` / `admin`.

## Use another provider

Override the defaults without editing source:

```shell
SIERE_OIDC_CLIENT_ID="your-public-client" \
SIERE_OIDC_DISCOVERY_URL="https://issuer.example/.well-known/openid-configuration" \
SIERE_OIDC_PROVIDER_ID="issuer.example" \
./gradlew :sample-jvm-oidc:run
```

The provider must register the application as a native/public client and accept
`http://127.0.0.1:<dynamic-port>/callback`. Never add a client secret to a desktop application.

## What to verify

1. The browser opens and Keycloak accepts the demo account.
2. The app displays the normalized name, email, and stable issuer/subject UID.
3. **Refresh session** performs a refresh-token grant without displaying credentials.
4. Restarting the app restores the encrypted local session.
5. **Sign out locally** deletes that session. The Keycloak browser cookie intentionally remains.

The default file store prevents plaintext token storage and uses owner-only permissions where the
operating system supports them. It is not a hardware-backed credential vault; production desktop
applications with that requirement should provide a `JvmOidcSessionStore` backed by the platform
keychain.
