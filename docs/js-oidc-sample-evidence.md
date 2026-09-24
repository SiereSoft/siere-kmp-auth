# Kotlin/JS OIDC live acceptance evidence

Status: **passed**

Date: 2026-09-24

Runtime digest: `049795cef5aea48fd169d1ac749cae2ba4ed509291032ad704ebfa649e9f3bea`

Browser: Google Chrome 153.0.8010.53 with its normal popup protection enabled.

## Candidate commands

```shell
./gradlew :sample-jvm-oidc:keycloakDown
./gradlew :sample-jvm-oidc:keycloakUp
./gradlew --no-parallel :sample:jsBrowserDistribution
python3 -m http.server 8081 --bind 127.0.0.1 \
  --directory sample/build/dist/js/productionExecutable
```

Keycloak started from a clean container and reported that realm `siere` was imported. The browser
loaded the production distribution from `http://127.0.0.1:8081`.

## Observed flow

1. **Local OIDC** was the selected provider and the sample displayed `Signed out`.
2. Clicking **Sign in with OpenID Connect** opened a separate Keycloak popup for client
   `siere-js-oidc`; the URL contained an S256 code challenge and the exact encoded callback.
3. The disposable `demo` / `demo-password` account completed login. The static server returned
   HTTP 200 for `/oidc-callback.html?...`, the popup closed, and the opener displayed
   `Signed in as Siere Demo`.
4. **Get fresh session** completed and displayed `Fresh session ready` for the Keycloak subject.
5. **Sign out** returned the sample to `Signed out`.

Chrome DevTools was opened on the completed candidate run. It showed four known Skiko WebGL
capability warnings and no errors. There was **No CORS error**, **No mixed-content error**,
**No token-bearing log**, and **No uncaught exception**.
The UI and successful code exchange/refresh also showed that discovery, token, and refresh requests
completed across the registered web origin. Neither the console nor the sample UI displayed an
access token, refresh token, ID token, authorization code, or callback query.
