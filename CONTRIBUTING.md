# Contributing

Thanks for helping improve Siere KMP Auth.

## Before you start

- Search existing issues and pull requests before proposing a change.
- Open an issue before beginning a large feature, provider integration, or public API change.
- Keep contributions focused and preserve the common, provider-neutral API.
- Never commit API keys, Firebase JSON or plist files, service-account credentials, OAuth secrets, signing assets, access tokens, or test accounts.

Sample applications must remain credential-free. Contributors provide their own local configuration and provider-console setup when exercising live authentication flows.

## Development

Use the included Gradle wrapper and JDK 17. Run the deterministic checks before requesting review:

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

Apple changes must use Swift Package Manager and the repository's Kotlin direct-integration workflow. Do not introduce CocoaPods.

## Pull requests

Include:

- a concise description of the behavior and supported platforms;
- tests covering success, failure, cancellation, and state-preservation behavior where applicable;
- API compatibility updates when public declarations change;
- emulator, simulator, or browser evidence for platform behavior that deterministic unit tests cannot prove;
- clear documentation of intentionally unsupported provider/platform combinations.

Do not include generated build output, local configuration, credentials, or unrelated project files.

By contributing, you agree that your contribution is licensed under the repository's Apache-2.0 license.
