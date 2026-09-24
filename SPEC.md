# Specification

## Intent

The credential-free Kotlin/JS sample demonstrates the published `auth-oidc` adapter against the
repository's disposable Keycloak server through a real browser popup and same-origin callback. Once
that flow is verified, document the implementation as the Kotlin/JS installment following the JVM,
Android, and iOS OIDC articles.

## Acceptance criteria

- The Kotlin/JS sample always offers a `Local OIDC` provider alongside Demo without requiring API
  keys or committed secrets.
- The JS UI calls `window.open()` synchronously in the same JavaScript click-handler stack as the
  OpenID button, before launching a coroutine or starting discovery. It reserves that
  `WindowProxy` for the attempt; after discovery the handler navigates the same popup and never
  opens a second window.
- `oidc-callback.html` posts a versioned, typed message containing only its complete callback URL to
  the exact target origin `http://127.0.0.1:8081`. It never uses `*`, logs the URL, or renders its
  query. The opener accepts the message exactly once only when the event origin is exact, its source
  is the active popup, its message type/version/value types match, and the parsed callback has
  exactly scheme `http`, host `127.0.0.1`, port `8081`, and path `/oidc-callback.html`.
- The production JS distribution contains a distinct `/oidc-callback.html` resource. A direct
  request returns that callback document with HTTP 200. The local server binds to
  `127.0.0.1:8081`; `localhost` is not interchangeable.
- The Keycloak fixture defines `siere-js-oidc` as a public Authorization Code client, requires PKCE
  `S256`, registers the exact callback, and permits only the sample origin through CORS.
- When synchronous `window.open()` returns `null`, the sample does not call `signInWithOpenId()` or
  start discovery and immediately displays the existing popup-blocked message.
- Closing the popup after the handler receives an authorization request is detected within 500 ms
  plus scheduling tolerance. The handler extracts the active state, returns a state-bound
  `access_denied` callback, and the library produces `AuthError.Cancelled`. Closing the blank popup
  during discovery marks the attempt cancelled; if discovery later succeeds, the handler returns
  the same state-bound cancellation without opening another popup. If discovery fails first, that
  network failure remains authoritative.
- Success, provider error, popup closure, discovery/token failure, coroutine cancellation, provider
  close, and page disposal all remove the message listener, cancel popup polling, release the active
  attempt, and close the popup when it is still open. A second click cannot orphan a popup.
- Tokens remain in the library's in-memory session store. The JS sample does not put access,
  refresh, or ID tokens in `localStorage`, the callback URL, or logs.
- Browser tests discover at least one test and cover: one valid message accepted; wrong origin;
  wrong or null source; wrong payload type/version; wrong scheme, host, port, or path; invalid then
  valid messages; duplicate or late messages; blocked popup before discovery; state-bound popup
  closure; and listener, timer, popup, and attempt cleanup. Rejection tests use a short pending
  assertion followed by a valid callback rather than waiting for the library timeout.
- The Keycloak fixture test verifies the exact singleton redirect and web-origin arrays, public
  client mode, standard flow, disabled implicit/direct/service-account flows, and PKCE `S256`.
- Against a clean Keycloak import and production JS distribution served on `127.0.0.1:8081`, a real
  Chromium-family browser with normal popup protection opens the popup from the UI click, signs in
  as `demo`, returns through the callback document, displays `Signed in as Siere Demo`, completes a
  forced refresh, and signs out. The console and network evidence contain no uncaught exception,
  token-bearing log, mixed-content error, or CORS error and record the candidate runtime digest,
  browser version, commands, and observed states.
- The sample README explains the local server, JS distribution server, callback, credentials,
  cleanup, and production limitations.
- The final article uses only behavior established by code, automated tests, and the live browser
  run. It links to maintained library instructions rather than freezing a dependency version.

## Failure behavior

- Wrong-origin, wrong-source, malformed, wrong-type, and wrong-path messages are ignored while the
  attempt remains pending. Query parameters from an accepted callback pass unchanged to the
  library, which rejects fragments. Late and duplicate messages are ignored.
- Popup blocking produces an immediate sample-visible `AuthError.PopupBlocked` message before a
  library operation begins.
- User popup closure produces an `access_denied` callback bound to the active state so the library
  returns its normal cancellation result.
- Keycloak/CORS/network failures remain typed library failures and do not replace Demo mode or
  expose credentials.

## Exclusions

- No durable browser token persistence. Browser `localStorage`, IndexedDB, cookies, and service
  workers are outside this sample.
- No silent SSO iframe, refresh in a background worker, RP-initiated logout, or popup fallback to a
  full-page redirect.
- No Wasm implementation in this phase; Wasm remains independently supported by the library.
- No production identity provider, production user data, connector, grant store, policy engine, or
  product UI.

## Approval boundaries

- Starting and stopping the repository's disposable local Keycloak container and local static
  server are authorized by the requested live test.
- Publishing, merging, releasing, or deploying remains outside this change unless separately
  requested.
