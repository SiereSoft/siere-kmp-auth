# Supabase provider

Use `auth-supabase` when Supabase Auth owns the user account and session. Version `0.2.0` supports
Android, iOS, JVM, JavaScript, and Wasm, and includes the matching Ktor engine for every target.

[Back to the project overview](../README.md)

## Feature support

`✓` means the operation is implemented on that target. `—` means it returns
`AuthError.Unsupported`. OAuth operations still require provider and redirect configuration in the
Supabase dashboard and host application.

| Capability | Android | iOS | JVM | JavaScript | Wasm |
|---|:---:|:---:|:---:|:---:|:---:|
| Observe and restore auth state | ✓ | ✓ | ✓ | ✓ | ✓ |
| Email sign-in, sign-up, and password reset | ✓ | ✓ | ✓ | ✓ | ✓ |
| Anonymous sign-in | ✓ | ✓ | ✓ | ✓ | ✓ |
| Phone sign-in | ✓ | ✓ | ✓ | ✓ | ✓ |
| Phone credential linking | — | — | — | — | — |
| Google sign-in and linking | ✓ | ✓ | ✓ | ✓ | ✓ |
| Apple sign-in and linking | ✓ | ✓ | ✓ | ✓ | ✓ |
| Fresh session and sign-out | ✓ | ✓ | ✓ | ✓ | ✓ |

Phone linking is deliberately disabled because the upstream phone-change verification flow is not
safely account-unique. Other phone operations use Supabase Auth directly.

## Add the dependency

After adding the GitHub Packages repository from the [project installation guide](../README.md#installation):

```kotlin
commonMain.dependencies {
    implementation("dev.siere.auth:auth-core:0.2.0")
    implementation("dev.siere.auth:auth-supabase:0.2.0")
}
```

## Supabase dashboard setup

1. Create or select a project and enable the authentication methods the application will expose.
2. Configure Google and Apple credentials when those OAuth providers are used.
3. Add every browser return URL or mobile deep-link callback to the redirect allow list.
4. Use a client-safe publishable key, or a legacy anonymous key. Never put a secret or service-role
   key in a client application.

## Email, phone, anonymous, JVM, and browser setup

For non-redirect operations, JVM applications, and browser redirect flows, construct the adapter
from the project URL and client-safe key:

```kotlin
val provider = SupabaseAuthProvider(
    supabaseUrl = consumerConfig.supabaseUrl,
    supabaseKey = consumerConfig.supabasePublishableKey,
)
val auth = SiereAuth(provider)
```

JavaScript and Wasm OAuth flows return through the current browser origin. Add that URL to the
Supabase redirect allow list. Inject reviewed public configuration at build or deploy time; do not
treat mutable `localStorage` as a trusted production configuration channel.

Phone sign-in is a two-step operation:

```kotlin
when (val started = auth.startPhoneSignIn(phoneNumber)) {
    is AuthResult.Success -> {
        val completed = started.value.confirm(codeFromUser)
        // Handle AuthResult<AuthUser>.
    }
    is AuthResult.Failure -> showError(started.error)
}
```

## Android and iOS OAuth redirects

Mobile Google and Apple flows must use one retained, application-owned `SupabaseClient`. Configure
its Auth plugin with the app's callback scheme and host, register the same deep link in the mobile
application and Supabase redirect allow list, and forward the returning URL to that client. Then
pass the same instance to Siere:

```kotlin
val supabaseClient = createSupabaseClient(
    supabaseUrl = consumerConfig.supabaseUrl,
    supabaseKey = consumerConfig.supabasePublishableKey,
) {
    install(Auth) {
        scheme = "myapp"
        host = "auth-callback"
    }
}

val auth = SiereAuth(SupabaseAuthProvider(supabaseClient))
```

Register `myapp://auth-callback` in the Supabase redirect allow list and in the Android manifest or
iOS URL types. On Android, call `supabaseClient.handleDeeplinks(intent)` from the activity handling
the intent. On iOS, pass the incoming URL to `supabaseClient.handleDeeplinks(url)`.

Do not create a second client when the callback arrives. The host application owns the supplied
client and remains responsible for closing it. The adapter waits for the redirect-driven session
transition with a bounded timeout; across navigation, always treat `authState` as the source of
truth.

## Calling the API

All supported targets use the same core operations:

```kotlin
auth.signInWithEmail(email, password)
auth.signUpWithEmail(email, password)
auth.sendPasswordReset(email)
auth.signInAnonymously()
auth.signInWithGoogle()
auth.signInWithApple()
auth.linkWithGoogle()
auth.linkWithApple()
auth.currentSession(forceRefresh = true)
auth.signOut()
```

Provider errors are mapped to typed `AuthError` values while retaining stable Supabase/GoTrue error
codes where available. OAuth linking also verifies that the session still belongs to the account
that started the operation.

## Lifecycle and security

- Call `currentSession(forceRefresh = true)` immediately before an authenticated backend request.
- Call `auth.close()` when the owner is disposed.
- If Siere created the Supabase client from URL/key, it closes that client asynchronously. If you
  supplied a client, your application retains ownership.
- Keep secret/service-role keys on trusted infrastructure only.
- Test redirect allow lists and deep-link routing with disposable development configuration before
  releasing the application.
